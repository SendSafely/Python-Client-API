import sys
from abc import ABC


class Progress(ABC):

    def __init__(self):
        self.progress = None

    def update_progress(self, file_id, progress):
        self.progress = progress
        
        if progress == '100.0':
            last = '\n'
        else:
            last = ''

        sys.stdout.write('\rProgress for fileId {0}: {1}{2} complete{3}'.format(file_id, progress, '%', last))
        sys.stdout.flush()
