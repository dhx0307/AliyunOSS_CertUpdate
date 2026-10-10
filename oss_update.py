import sys
import argparse
from datetime import datetime, timezone

import oss2
from oss2.models import CnameInfo

class OSS:
    def __init__(self, access_key_id: str, access_key_secret: str, endpoint: str, bucket_name: str, region: str = "cn-hangzhou"):
        self.auth = oss2.AuthV4(access_key_id, access_key_secret)
        self.endpoint = endpoint
        self.bucket_name = bucket_name
        self.region = region
        self.bucket = oss2.Bucket(self.auth, self.endpoint, bucket_name=self.bucket_name, region=self.region)

    def run_update(self, target_cname: str, private_key: str, certificate: str):
        cname_info = self._get_matched_cname(target_cname)
        if cname_info and private_key and certificate:
            self._update_cname(cname_info, private_key, certificate)
        else:
            print("未找到匹配的自定义域名或证书信息不完整")
            sys.exit(1)

    def _get_matched_cname(self, target_cname: str) -> CnameInfo | None:
        cname_list = self._get_cname_info()
        for c in cname_list:
            if c.domain == target_cname:
                return c
        return None

    def _get_cname_info(self, isprint: bool = True) -> list:
        list_result = self.bucket.list_bucket_cname()
        if isprint:
            for c in list_result.cname:
                print(f"证书 ID ： {getattr(c.certificate, 'cert_id', None)}")  # 打印证书ID
                print(f"自定义域名： {c.domain}")  # 打印自定义域名
                print(f"最后修改时间： {c.last_modified}")  # 打印绑定自定义域名的时间
        return list_result.cname

    @staticmethod
    def _parse_expire(cert) -> datetime | None:
        """解析旧证书到期时间；字段为空（如阿里云证书服务 CAS 托管的证书）或格式不认识时返回 None。"""
        value = getattr(cert, 'valid_end_date', None)
        if not value:
            return None
        for fmt in ('%b %d %H:%M:%S %Y GMT', '%Y-%m-%dT%H:%M:%S.%fZ', '%Y-%m-%dT%H:%M:%SZ'):
            try:
                return datetime.strptime(value, fmt).replace(tzinfo=timezone.utc)
            except ValueError:
                continue
        return None

    def _put_cname(self, domain: str, cert):
        input_ = oss2.models.PutBucketCnameRequest(domain, cert)
        self.bucket.put_bucket_cname(input_)

    def _update_cname(self, cname_info: CnameInfo, private_key: str, certificate: str):
        old_cert = cname_info.certificate
        old_cert_id = getattr(old_cert, 'cert_id', None) if old_cert else None
        expire = self._parse_expire(old_cert) if old_cert else None

        # 没有绑定证书，或者能确认旧证书已过期 -> 创建新证书
        # 绑定了证书且（未过期，或到期时间未知，例如 CAS 证书）-> 用 previous_cert_id 替换
        replace_mode = bool(old_cert_id) and not (expire is not None and expire <= datetime.now(timezone.utc))

        new_cert = oss2.models.CertInfo(certificate=certificate, private_key=private_key, force=True)

        if not replace_mode:
            print("证书已过期或未绑定证书，将创建新的证书")
            self._put_cname(cname_info.domain, new_cert)
            return

        if expire is None:
            print("旧证书未返回到期时间（可能是阿里云证书服务托管的证书），将直接替换。当前证书信息如下：")
        else:
            print("证书未过期，将更新证书。当前证书信息如下：")
        print(vars(old_cert))

        replace_cert = oss2.models.CertInfo(previous_cert_id=old_cert_id,
                                            certificate=certificate, private_key=private_key, force=True)
        try:
            self._put_cname(cname_info.domain, replace_cert)
        except oss2.exceptions.OssError as e:
            # 替换失败时，退回到“直接绑定新证书”的方式再试一次
            print(f"替换旧证书失败（{e.code}），改为直接绑定新证书重试")
            self._put_cname(cname_info.domain, new_cert)


def main():
    parser = argparse.ArgumentParser(description="Aliyun OSS 证书自动更新脚本")
    parser.add_argument('--access-key-id', required=True, help='阿里云 AccessKeyId')
    parser.add_argument('--access-key-secret', required=True, help='阿里云 AccessKeySecret')
    parser.add_argument('--endpoint', required=True, help='OSS Endpoint')
    parser.add_argument('--bucket-name', required=True, help='OSS Bucket 名称')
    parser.add_argument('--target-cname', required=True, help='需要更新证书的自定义域名')
    parser.add_argument('--private-key', required=True, help='证书私钥内容')
    parser.add_argument('--certificate', required=True, help='证书内容')
    parser.add_argument('--region', default='cn-hangzhou', help='OSS 区域，默认为 cn-hangzhou')

    args = parser.parse_args()

    oss = OSS(
        access_key_id=args.access_key_id,
        access_key_secret=args.access_key_secret,
        endpoint=args.endpoint,
        bucket_name=args.bucket_name,
        region=args.region
    )
    oss.run_update(args.target_cname, args.private_key, args.certificate)


if __name__ == "__main__":
    main()
