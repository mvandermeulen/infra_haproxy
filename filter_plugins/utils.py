from re import sub as regex_replace


class FilterModule(object):
    def filters(self):
        return {
            "ensure_list": self.ensure_list,
            "is_string": self.is_string,
            "is_dict": self.is_dict,
            "safe_key": self.safe_key,
            "ssl_fingerprint_active": self.ssl_fingerprint_active,
            "ssl_fingerprint_ja4": self.ssl_fingerprint_ja4,
            "build_route": self.build_route,
            "join_w_excludes": self.join_w_excludes,
            "waf_coraza_apps": self.waf_coraza_apps,
            "all_route_backends_exist": self.all_route_backends_exist,
        }

    @staticmethod
    def ensure_list(data: (str, list)) -> list:
        # if user supplied a string instead of a list => convert it to match our expectations
        if isinstance(data, list):
            return data

        return [data]

    @staticmethod
    def is_string(data) -> bool:
        return isinstance(data, str)

    @staticmethod
    def is_dict(data) -> bool:
        return isinstance(data, dict)

    @staticmethod
    def safe_key(key: str) -> str:
        return regex_replace('[^0-9a-zA-Z_]+', '', key.replace(' ', '_'))

    @staticmethod
    def ssl_fingerprint_active(frontends: dict) -> bool:
        for fe_cnf in frontends.values():
            try:
                if fe_cnf['security']['fingerprint_ssl']:
                    return True

            except KeyError:
                continue

        return False

    @staticmethod
    def ssl_fingerprint_ja4(frontends: dict, defaults_frontend: dict) -> bool:
        for fe_cnf in frontends.values():
            try:
                if fe_cnf['security']['fingerprint_ssl_type'].lower() == 'ja4':
                    return True

            except KeyError:
                try:
                    if defaults_frontend['security']['fingerprint_ssl_type'].lower() == 'ja4':
                        return True

                except KeyError:
                    continue

        return False

    @staticmethod
    def is_truthy(v: (bool, str, int)) -> bool:
        return v in [True, 'yes', 'y', 'Yes', 'YES', 'true', 1, '1']

    @classmethod
    def join_w_excludes(cls, v: list, excludes: list) -> str:
        return ' '.join([v for v in cls.ensure_list(v) if v not in cls.ensure_list(excludes)])

    # pylint: disable=R0912,R0915
    @classmethod
    def build_route(cls, fe_cnf: dict, be_cnf: dict, be_name: str, only_condition: bool = False) -> (list, str):
        lines = []
        to_match = []
        var_prefix = f'{be_name}_filter'

        if fe_cnf['mode'] == 'http' and len(be_cnf['domains']) > 0:
            lines.append(
                f"acl {var_prefix}_domains req.hdr(host) "
                f"-m str -i {' '.join(cls.ensure_list(be_cnf['domains']))}"
            )
            to_match.append(f'{var_prefix}_domains')

        if len(be_cnf['filter_ip']) > 0:
            lines.append(f"acl {var_prefix}_ip src {' '.join(cls.ensure_list(be_cnf['filter_ip']))}")
            to_match.append(f'{var_prefix}_ip')

        if len(be_cnf['filter_not_ip']) > 0:
            lines.append(f"acl {var_prefix}_not_ip src {' '.join(cls.ensure_list(be_cnf['filter_not_ip']))}")
            to_match.append(f'!{var_prefix}_not_ip')

        if len(be_cnf['filter_acl']) > 0:
            to_match.extend(cls.ensure_list(be_cnf['filter_acl']))

        if len(be_cnf['filter_not_acl']) > 0:
            to_match.extend([f'!{a}' for a in cls.ensure_list(be_cnf['filter_acl'])])

        if cls.is_truthy(fe_cnf['geoip']['enable']):
            if cls.is_truthy(fe_cnf['geoip']['country']):
                if len(be_cnf['filter_country']) > 0:
                    lines.append(
                        f"acl {var_prefix}_country var(txn.geoip_country) "
                        f"-m str -i {' '.join(cls.ensure_list(be_cnf['filter_country']))}"
                    )
                    to_match.append(f'{var_prefix}_country')

                if len(be_cnf['filter_not_country']) > 0:
                    lines.append(
                        f"acl {var_prefix}_not_country var(txn.geoip_country) "
                        f"-m str -i {' '.join(cls.ensure_list(be_cnf['filter_not_country']))}"
                    )
                    to_match.append(f'!{var_prefix}_not_country')

            if cls.is_truthy(fe_cnf['geoip']['asn']):
                if len(be_cnf['filter_asn']) > 0:
                    lines.append(
                        f"acl {var_prefix}_asn var(txn.geoip_asn) "
                        f"-m str -i {' '.join(cls.ensure_list(be_cnf['filter_asn']))}"
                    )
                    to_match.append(f'{var_prefix}_asn')

                if len(be_cnf['filter_not_asn']) > 0:
                    lines.append(
                        f"acl {var_prefix}_not_asn var(txn.geoip_asn) "
                        f"-m str -i {' '.join(cls.ensure_list(be_cnf['filter_not_asn']))}"
                    )
                    to_match.append(f'!{var_prefix}_not_asn')

        be_statics_name = None
        statics_to_match = []
        if 'statics' in be_cnf and 'locations' in be_cnf['statics'] \
                and len(be_cnf['statics']['locations']) > 0 and str(be_cnf['statics']['backend']).strip() != '':
            be_statics_name = be_cnf['statics']['backend']
            statics_to_match = to_match.copy()

            lines.append(
                f"acl {var_prefix}_statics path "
                f"-i -m beg {' '.join(cls.ensure_list(be_cnf['statics']['locations']))}"
            )
            to_match.append(f'!{var_prefix}_statics')
            statics_to_match.append(f'{var_prefix}_statics')

        condition = ''
        for loop_be, loop_match in {
            be_name: to_match,
            be_statics_name: statics_to_match
        }.items():
            if loop_be is None:
                continue

            if len(loop_match) > 0:
                if cls.is_truthy(be_cnf['filter_match_or']):
                    loop_match_or = []
                    if len(be_cnf['domains']) == 0:
                        loop_match_or = loop_match

                    else:
                        d = loop_match[0]
                        for m in loop_match[1:]:
                            loop_match_or.append(f'{d} {m}')

                    condition = f"if {' || '.join(loop_match_or)}"
                    lines.append(f"use_backend {loop_be} {condition}")

                else:
                    condition = f"if {' '.join(loop_match)}"
                    lines.append(f"use_backend {loop_be} {condition}")

            else:
                lines.append(f"use_backend {loop_be}")

        if only_condition:
            return condition

        return lines

    @staticmethod
    def waf_coraza_apps(waf_cnf: dict) -> list:
        if not isinstance(waf_cnf, dict) or 'apps' not in waf_cnf or not isinstance(waf_cnf['apps'], list):
            return []

        apps = []
        for app in waf_cnf['apps']:
            try:
                apps.append(app['name'])

            except KeyError:
                pass

        return apps

    @classmethod
    def all_route_backends_exist(cls, cnf: dict) -> bool:
        existing_be_names = [cls.safe_key(name) for name in cnf['backends']]

        for fe_cnf in cnf['frontends'].values():
            for be_name_user in fe_cnf['routes']:
                be_name = cls.safe_key(be_name_user)
                if be_name not in existing_be_names:
                    return False

        return True
