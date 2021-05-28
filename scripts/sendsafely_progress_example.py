import sys

from sendsafely import SendSafely, Package, Progress


class CustomProgress(Progress):

    def update_progress(self, file_id, progress):
        self.progress = progress

        if progress == '100.0':
            last = '\n'
        else:
            last = ''

        sys.stdout.write('\rCustom Progress for fileId {0}: {1}{2} complete{3}'.format(file_id, progress, '%', last))
        sys.stdout.flush()


sendsafely = SendSafely("https://companyabc.sendsafely.com", "", "")
package = Package(sendsafely)
recipient = "me@sendsafely.net"
recipient = package.add_recipient(recipient)
test_file_path = "fileToUpload.txt"
# custom case
custom = package.encrypt_and_upload_file(test_file_path, progress_instance=CustomProgress())
# default case
default = package.encrypt_and_upload_file(test_file_path)
