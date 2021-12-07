package tools

import "github.com/sirupsen/logrus"

func NewFatalLogger() *logrus.Logger {
	log := logrus.New()
	log.Level = logrus.FatalLevel
	return log
}
