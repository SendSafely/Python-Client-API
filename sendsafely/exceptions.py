class CreatePackageFailedException(Exception):
    """Exception raised during failed package creation.
    """
    def __init__(self, details=None):
        self.message = "An error occurred during package creation."
        self.details = details
        display = self.details
        if display is None:
            display = self.message
        super().__init__(display)

class InvalidCredentialsException(Exception):
    """Exception raised due to invalid credentials.
    """
    def __init__(self, details=None):
        self.message = "An error occurred due to invalid credentials."
        self.details = details
        display = self.details
        if display is None:
            display = self.message
        super().__init__(display)


class UpdatePackageException(Exception):
    """Exception raised during package update.
    """
    def __init__(self, details=None):
        self.message = "An error occurred during package update."
        self.details = details
        display = self.details
        if display is None:
            display = self.message
        super().__init__(display)


class DeletePackageException(Exception):
    """Exception raised during package deletion.
    """
    def __init__(self, details=None):
        self.message = "An error occurred during package deletion."
        self.details = details
        display = self.details
        if display is None:
            display = self.message
        super().__init__(display)


class DeleteFileException(Exception):
    """Exception raised during package file deletion.
    """
    def __init__(self, details=None):
        self.message = "An error occurred during package file deletion."
        self.details = details
        display = self.details
        if display is None:
            display = self.message
        super().__init__(display)


class DeleteDirectoryException(Exception):
    """Exception raised during Workspace directory deletion.
    """
    def __init__(self, details=None):
        self.message = "An error occurred during Workspace directory deletion."
        self.details = details
        display = self.details
        if display is None:
            display = self.message
        super().__init__(display)


class RenameDirectoryException(Exception):
    """Exception raised while trying to rename a Workspace directory.
    """
    def __init__(self, details=None):
        self.message = "An error occurred while trying to rename a Workspace directory."
        self.details = details
        display = self.details
        if display is None:
            display = self.message
        super().__init__(display)


class FinalizePackageFailedException(Exception):
    """Exception raised while finalizing package.
    """
    def __init__(self, details=None):
        self.message = "An error occurred during finalize package."
        self.details = details
        display = self.details
        if display is None:
            display = self.message
        super().__init__(display)


class DownloadFileException(Exception):
    """Exception raised during a file download.
    """
    def __init__(self, details=None):
        self.message = "An error occurred during file download."
        self.details = details
        display = self.details
        if display is None:
            display = self.message
        super().__init__(display)


class AddRecipientFailedException(Exception):
    """Exception raised while adding a recipient..
    """
    def __init__(self, details=None):
        self.message = "An error occurred while adding a recipient."
        self.details = details
        display = self.details
        if display is None:
            display = self.message
        super().__init__(display)


class AddFileFailedException(Exception):
    """Exception raised while adding a file to a package.
    """
    def __init__(self, details=None):
        self.message = "An error occurred while adding a file to a package."
        self.details = details
        display = self.details
        if display is None:
            display = self.message
        super().__init__(display)


class GetKeycodeFailedException(Exception):
    """Exception raised while getting keycode.
    """
    def __init__(self, details=None):
        self.message = "An error occurred while getting keycode."
        self.details = details
        display = self.details
        if display is None:
            display = self.message
        super().__init__(display)


class UpdateRecipientFailedException(Exception):
    """Exception raised while updating a recipient.
    """
    def __init__(self, details=None):
        self.message = "An error occurred while updating a recipient."
        self.details = details
        display = self.details
        if display is None:
            display = self.message
        super().__init__(display)


class UploadMessageException(Exception):
    """Exception raised while uploading a message.
    """
    def __init__(self, details=None):
        self.message = "An error occurred while uploading a message."
        self.details = details
        display = self.details
        if display is None:
            display = self.message
        super().__init__(display)


class GetPublicKeysFailedException(Exception):
    """Exception raised while getting public keys.
    """
    def __init__(self, details=None):
        self.message = "An error occurred while getting public keys."
        self.details = details
        display = self.details
        if display is None:
            display = self.message
        super().__init__(display)


class UploadFileException(Exception):
    """Exception raised during a file upload.
    """
    def __init__(self, details=None):
        self.message = "An error occurred during file upload."
        self.details = details
        display = self.details
        if display is None:
            display = self.message
        super().__init__(display)


class GetFileInformationException(Exception):
    """Exception raised while getting file information.
    """
    def __init__(self, details=None):
        self.message = "An error occurred while getting file information."
        self.details = details
        display = self.details
        if display is None:
            display = self.message
        super().__init__(display)


class GetUserInformationException(Exception):
    """Exception raised while getting user information.
    """
    def __init__(self, details=None):
        self.message = "An error occurred while getting user information."
        self.details = details
        display = self.details
        if display is None:
            display = self.message
        super().__init__(display)


class TrustedDeviceException(Exception):
    """Exception raised while generating/revoking a trusted device.
    """
    def __init__(self, details=None):
        self.message = "An error occurred while generating/revoking a trusted device."
        self.details = details
        display = self.details
        if display is None:
            display = self.message
        super().__init__(display)


class GetPackagesException(Exception):
    """Exception raised while getting packages.
    """
    def __init__(self, details=None):
        self.message = "An error occurred while retrieving packages."
        self.details = details
        display = self.details
        if display is None:
            display = self.message
        super().__init__(display)


class GetPackageMessageException(Exception):
    """Exception raised while getting package message.
    """
    def __init__(self, details=None):
        self.message = "An error occurred while getting the package message."
        self.details = details
        display = self.details
        if display is None:
            display = self.message
        super().__init__(display)


class LimitExceededException(Exception):
    """Exception that indicates an exceeded limit.
    """
    def __init__(self, details=None):
        self.message = "An error occurred because the limit was exceeded."
        self.details = details
        display = self.details
        if display is None:
            display = self.message
        super().__init__(display)


class GetPackageInformationFailedException(Exception):
    """Exception that occurs during get_package_information.
    """
    def __init__(self, details=None):
        self.message = "An error occurred while getting package information."
        self.details = details
        display = self.details
        if display is None:
            display = self.message
        super().__init__(display)


class UploadKeycodeException(Exception):
    """Exception that occurs while uploading keycode.
    """
    def __init__(self, details=None):
        self.message = "An error occurred while uploading keycode."
        self.details = details
        display = self.details
        if display is None:
            display = self.message
        super().__init__(display)


class KeycodeRequiredException(Exception):
    """Operation is blocked because the package was not initialized with a keycode
    """
    def __init__(self, details=None):
        self.message = "This operation is blocked because this package was not initialized with a keycode."
        self.details = details
        display = self.details
        if display is None:
            display = self.message
        super().__init__(display)


class MoveFileException(Exception):
    """Exception that occurs while attempting to move a Workspace file
    """
    def __init__(self, details=None):
        self.message = "An error occurred while attempting to move a Workspace file."
        self.details = details
        display = self.details
        if display is None:
            display = self.message
        super().__init__(display)


class MoveDirectoryException(Exception):
    """Exception that occurs while attempting to move a Workspace directory
    """
    def __init__(self, details=None):
        self.message = "An error occurred while attempting to move a Workspace directory."
        self.details = details
        display = self.details
        if display is None:
            display = self.message
        super().__init__(display)

class CreateDirectoryException(Exception):
    """Exception that occurs while creating a Workspace subdirectory
    """
    def __init__(self, details=None):
        self.message = "An error occurred while attempting to create a Workspace directory."
        self.details = details
        display = self.details
        if display is None:
            display = self.message
        super().__init__(display)

class GetDirectoryException(Exception):
    """Exception that occurs while attempting to get Directory information
    """
    def __init__(self, details=None):
        self.message = "An error occurred while getting Directory information."
        self.details = details
        display = self.details
        if display is None:
            display = self.message
        super().__init__(display)