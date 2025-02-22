// Code generated by mockery v1.0.0. DO NOT EDIT.

package mocks

import (
	autorest "github.com/Azure/go-autorest/autorest"

	mock "github.com/stretchr/testify/mock"
)

// IAzureAuthroizerFactory is an autogenerated mock type for the IAzureAuthroizerFactory type
type IAzureAuthroizerFactory struct {
	mock.Mock
}

// CreateARMAuthorizer provides a mock function with given fields:
func (_m *IAzureAuthroizerFactory) CreateARMAuthorizer() (autorest.Authorizer, error) {
	ret := _m.Called()

	var r0 autorest.Authorizer
	if rf, ok := ret.Get(0).(func() autorest.Authorizer); ok {
		r0 = rf()
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(autorest.Authorizer)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func() error); ok {
		r1 = rf()
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}
