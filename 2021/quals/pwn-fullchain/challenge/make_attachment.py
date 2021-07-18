# Copyright 2021 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
import argparse
import hashlib
import io
import os
import sys
import zipfile

def add_file(zipf, fpath, zpath):
    print(f'Adding {zpath}...')
    zipinfo = zipfile.ZipInfo(zpath, date_time=(1980, 0, 0, 0, 0, 0))
    zipinfo.external_attr = 0o644 << 16
    with open(fpath, 'rb') as f:
        zipf.writestr(zipinfo, f.read(), compress_type=zipfile.ZIP_DEFLATED)


def main():
    script_path = os.path.dirname(os.path.realpath(__file__))
    parser = argparse.ArgumentParser(
      description='Create the attachments for the fullchain challenge')
    parser.add_argument('--bucket', dest='bucket', required=True,
                        help='GCS bucket name for the attachments')
    args = parser.parse_args()

    zip_output = io.BytesIO()
    with zipfile.ZipFile(zip_output, 'w', compression=zipfile.ZIP_DEFLATED) as zipf:
        for root, _, files in sorted(os.walk(os.path.join(script_path, '..', 'attachments'), followlinks=True)):
            for f in sorted(files):
                fpath = os.path.join(root, f)
                add_file(zipf, fpath, f)

        for root, _, files in sorted(os.walk(os.path.join(script_path, 'chromium'), followlinks=True)):
            for f in sorted(files):
                fpath = os.path.join(root, f)
                zpath = fpath.replace(script_path, '').lstrip('/')
                add_file(zipf, fpath, zpath)

        add_file(zipf, os.path.join(script_path, 'rootfs.img'), 'rootfs.img')

    attachment_zip_data = zip_output.getvalue()
    digest = hashlib.sha512(attachment_zip_data).hexdigest()
    with open(digest, 'wb') as f:
        f.write(attachment_zip_data)

    print(f'HTTP URL https://storage.cloud.google.com/{args.bucket}/{digest}')
    print(f'GS URL gs://{args.bucket}/{digest}')
    print(f'Now run \'gsutil cp {digest} gs://{args.bucket}/')
    print("Don't forget to update metadata.yaml and download_files_from_gcs.sh")

if __name__ == '__main__':
    main()
