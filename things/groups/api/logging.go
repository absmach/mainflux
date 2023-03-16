package api

import (
	"context"
	"fmt"
	"time"

	log "github.com/mainflux/mainflux/logger"
	"github.com/mainflux/mainflux/things/groups"
)

var _ groups.Service = (*loggingMiddleware)(nil)

type loggingMiddleware struct {
	logger log.Logger
	svc    groups.Service
}

func LoggingMiddleware(svc groups.Service, logger log.Logger) groups.Service {
	return &loggingMiddleware{logger, svc}
}

func (lm *loggingMiddleware) CreateGroups(ctx context.Context, token string, group ...groups.Group) (rGroup []groups.Group, err error) {
	defer func(begin time.Time) {
		message := fmt.Sprintf("Method create_channel for %d channels using token %s took %s to complete", len(group), token, time.Since(begin))
		if err != nil {
			lm.logger.Warn(fmt.Sprintf("%s with error: %s.", message, err))
			return
		}
		lm.logger.Info(fmt.Sprintf("%s without errors.", message))
	}(time.Now())
	return lm.svc.CreateGroups(ctx, token, group...)
}

func (lm *loggingMiddleware) UpdateGroup(ctx context.Context, token string, group groups.Group) (rGroup groups.Group, err error) {
	defer func(begin time.Time) {
		message := fmt.Sprintf("Method update_channel for channel with id %s using token %s took %s to complete", group.ID, token, time.Since(begin))
		if err != nil {
			lm.logger.Warn(fmt.Sprintf("%s with error: %s.", message, err))
			return
		}
		lm.logger.Info(fmt.Sprintf("%s without errors.", message))
	}(time.Now())
	return lm.svc.UpdateGroup(ctx, token, group)
}

func (lm *loggingMiddleware) ViewGroup(ctx context.Context, token, id string) (g groups.Group, err error) {
	defer func(begin time.Time) {
		message := fmt.Sprintf("Method view_channel for channel with id %s using token %s took %s to complete", g.Name, token, time.Since(begin))
		if err != nil {
			lm.logger.Warn(fmt.Sprintf("%s with error: %s.", message, err))
			return
		}
		lm.logger.Info(fmt.Sprintf("%s without errors.", message))
	}(time.Now())
	return lm.svc.ViewGroup(ctx, token, id)
}

func (lm *loggingMiddleware) ListGroups(ctx context.Context, token string, gp groups.GroupsPage) (cg groups.GroupsPage, err error) {
	defer func(begin time.Time) {
		message := fmt.Sprintf("Method list_channels using token %s took %s to complete", token, time.Since(begin))
		if err != nil {
			lm.logger.Warn(fmt.Sprintf("%s with error: %s.", message, err))
			return
		}
		lm.logger.Info(fmt.Sprintf("%s without errors.", message))
	}(time.Now())
	return lm.svc.ListGroups(ctx, token, gp)
}

func (lm *loggingMiddleware) EnableGroup(ctx context.Context, token string, id string) (g groups.Group, err error) {
	defer func(begin time.Time) {
		message := fmt.Sprintf("Method enable_channel for channel with id %s using token %s took %s to complete", id, token, time.Since(begin))
		if err != nil {
			lm.logger.Warn(fmt.Sprintf("%s with error: %s.", message, err))
			return
		}
		lm.logger.Info(fmt.Sprintf("%s without errors.", message))
	}(time.Now())
	return lm.svc.EnableGroup(ctx, token, id)
}

func (lm *loggingMiddleware) DisableGroup(ctx context.Context, token string, id string) (g groups.Group, err error) {
	defer func(begin time.Time) {
		message := fmt.Sprintf("Method disable_channel for channel with id %s using token %s took %s to complete", id, token, time.Since(begin))
		if err != nil {
			lm.logger.Warn(fmt.Sprintf("%s with error: %s.", message, err))
			return
		}
		lm.logger.Info(fmt.Sprintf("%s without errors.", message))
	}(time.Now())
	return lm.svc.DisableGroup(ctx, token, id)
}

func (lm *loggingMiddleware) ListMemberships(ctx context.Context, token, thingID string, cp groups.GroupsPage) (mp groups.MembershipsPage, err error) {
	defer func(begin time.Time) {
		message := fmt.Sprintf("Method list_channels_by_thing for thing with id %s using token %s took %s to complete", thingID, token, time.Since(begin))
		if err != nil {
			lm.logger.Warn(fmt.Sprintf("%s with error: %s.", message, err))
			return
		}
		lm.logger.Info(fmt.Sprintf("%s without errors.", message))
	}(time.Now())
	return lm.svc.ListMemberships(ctx, token, thingID, cp)
}
