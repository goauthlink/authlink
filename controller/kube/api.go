// Copyright 2025 The AuthLink Authors. All rights reserved.
// Use of this source code is governed by an Apache2
// license that can be found in the LICENSE file.

package kube

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/goauthlink/authlink/controller/apis/generated/clientset/versioned"
	informers "github.com/goauthlink/authlink/controller/apis/generated/informers/externalversions"
	v1beta1 "github.com/goauthlink/authlink/controller/apis/generated/informers/externalversions/policies/v1beta1"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/tools/clientcmd"
)

const resyncTime = 5 * time.Minute

type Api struct {
	logger *slog.Logger

	kubeClient versioned.Interface
	polices    v1beta1.PolicyInformer

	sharedInformers informers.SharedInformerFactory
	syncChecks      []cache.InformerSynced
}

func NewApi(kubeConfig string, logger *slog.Logger) (*Api, error) {
	cfg, err := clientcmd.BuildConfigFromFlags("", kubeConfig)
	if err != nil {
		return nil, fmt.Errorf("error building kubeconfig: %w", err)
	}

	kubeClient, err := versioned.NewForConfig(cfg)
	if err != nil {
		return nil, fmt.Errorf("error building kubernetes clientset: %w", err)
	}

	return initApi(kubeClient, logger), nil
}

func initApi(kubeClient versioned.Interface, logger *slog.Logger) *Api {
	api := &Api{
		logger:          logger,
		kubeClient:      kubeClient,
		syncChecks:      []cache.InformerSynced{},
		sharedInformers: informers.NewSharedInformerFactory(kubeClient, resyncTime),
	}

	api.polices = api.sharedInformers.Authlink().V1beta1().Policies()
	api.syncChecks = append(api.syncChecks, api.polices.Informer().HasSynced)
	api.polices.Informer().GetIndexer().Add(kubeClient)

	return api
}

func (api *Api) Policies() v1beta1.PolicyInformer {
	return api.polices
}

func (api *Api) Sync(ctx context.Context) error {
	api.sharedInformers.Start(ctx.Done())

	api.logger.Info("waiting for caches to sync")
	if !cache.WaitForCacheSync(ctx.Done(), api.syncChecks...) {
		return errors.New("failed to sync caches")
	}
	api.logger.Info("caches synced")

	return nil
}
