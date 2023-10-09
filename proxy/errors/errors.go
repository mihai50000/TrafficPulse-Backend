package errors

type WindowsNotContinuousError struct {
	message string
}

func (err WindowsNotContinuousError) Error() string {
	return err.message
}

func NewWindowsNotContinuousError(message string) WindowsNotContinuousError {
	return WindowsNotContinuousError{message: message}
}
