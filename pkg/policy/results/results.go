package results

import "fmt"

type verificationStatus string

type Verification struct {
	status  verificationStatus
	message string
	err     error
}

const (
	verificationStatusFail    = "fail"
	verificationStatusAudit   = "audit"
	verificationStatusPass    = "pass"
	verificationStatusInvalid = "invalid"
)

func VerificationFail(err error) Verification {
	return Verification{
		status: verificationStatusFail,
		err:    err,
	}
}

func VerificationInvalid(err error) Verification {
	return Verification{
		status: verificationStatusInvalid,
		err:    err,
	}
}

func VerificationPass() Verification {
	return Verification{
		status: verificationStatusPass,
	}
}

func VerificationAudit(message string) Verification {
	return Verification{
		status:  verificationStatusAudit,
		message: message,
	}
}

func (v Verification) Pass() bool {
	return v.status == verificationStatusPass
}

func (v Verification) Fail() bool {
	return v.status == verificationStatusFail
}

func (v Verification) Audit() bool {
	return v.status == verificationStatusAudit
}

func (v Verification) String() string {
	switch v.status {
	case verificationStatusPass:
		return "PASS"
	case verificationStatusFail:
		return fmt.Sprintf("FAIL: %v", v.err)
	case verificationStatusAudit:
		return fmt.Sprintf("AUDIT: %v", v.message)
	case verificationStatusInvalid:
		return fmt.Sprintf("INVALID: %v", v.err)
	default:
		panic("internal error")
	}
}
