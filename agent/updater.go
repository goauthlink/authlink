package agent

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"time"
)

type updater struct {
	periodSeconds  int
	policyFilePath string
	dataFilePath   string
	logger         *slog.Logger
	policy         *Policy
}

func newUpdater(config Config, logger *slog.Logger, policy *Policy) *updater {
	return &updater{
		periodSeconds:  config.UpdateFilesSeconds,
		policyFilePath: config.PolicyFilePath,
		dataFilePath:   config.DataFilePath,
		logger:         logger,
		policy:         policy,
	}
}

func (u *updater) Name() string {
	return "policy updater"
}

func (u *updater) Start(ctx context.Context) error {
	ticker := time.NewTicker(time.Second * time.Duration(u.periodSeconds))

	for {
		select {
		case <-ticker.C:
			if err := u.updateFiles(); err != nil {
				u.logger.Error(fmt.Sprintf("updating files failed: %s", err.Error()))
			}
		case <-ctx.Done():
			u.logger.Info("stop updating files")
			return nil
		}
	}
}

func (u *updater) Shutdown(_ context.Context) error {
	return nil
}

func (u *updater) updateFiles() error {
	policyData, err := os.ReadFile(u.policyFilePath)
	if err != nil {
		return fmt.Errorf("policy file updating failed: %w", err)
	}
	if err := u.policy.SetPolicy(policyData); err != nil {
		return fmt.Errorf("policy file updating failed: %w", err)
	}
	u.logger.Info("policy file updated")

	if len(u.dataFilePath) == 0 {
		return nil
	}

	data, err := os.ReadFile(u.dataFilePath)
	if err != nil {
		return fmt.Errorf("data file updating failed: %s", err)
	}

	if err := u.policy.SetData(data); err != nil {
		return fmt.Errorf("loading data.json: %w", err)
	}

	u.logger.Info("data file updated")

	return nil
}
