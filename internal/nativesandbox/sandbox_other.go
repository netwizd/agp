//go:build !linux

package nativesandbox

import "context"

type Runner struct{}

func NewAsUser(Tool, uint32, uint32) (*Runner, error)     { return nil, ErrUnavailable }
func New(Tool) (*Runner, error)                           { return nil, ErrUnavailable }
func (*Runner) Binding() Binding                          { return Binding{} }
func (*Runner) run(context.Context, Spec, []string) error { return ErrUnavailable }
func ApplyLocalProcessLimits() error                      { return ErrUnavailable }
func CheckLimits() error                                  { return ErrUnavailable }
