/*
 * Teleport
 * Copyright (C) 2025  Gravitational, Inc.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

package awsra

import (
	"context"
	"log/slog"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/arn"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/rolesanywhere"
	ratypes "github.com/aws/aws-sdk-go-v2/service/rolesanywhere/types"
	"github.com/google/uuid"
	"github.com/gravitational/trace"
	"github.com/jonboulle/clockwork"

	"github.com/gravitational/teleport/api/types"
)

// AWSRolesAnywherProfileSyncerParams contains the parameters for the AWS Roles Anywhere Profile Syncer.
type AWSRolesAnywherProfileSyncerParams struct {
	// Logger is used to log messages.
	Logger *slog.Logger

	// Clock is used to calculate the expiration time of the AppServers.
	Clock clockwork.Clock

	// HostUUID is the Host UUID to assign to the AppServers.
	HostUUID string

	// KeyStoreManager grants access to the AWS Roles Anywhere signer.
	KeyStoreManager KeyStoreManager

	// Cache is used to get the current cluster name and cert authority keys.
	Cache Cache

	// IntegrationLister is used to list integrations.
	IntegrationLister IntegrationLister

	// SubjectName is the name of the subject to use when generating AWS credentials.
	SubjectName string

	// SyncPollInterval is the interval at which to poll for new profiles.
	// Default is 10 seconds.
	SyncPollInterval time.Duration

	// AppServerPublicURLFn is used to generate the public URL for the AppServer.
	AppServerPublicURLFn func(profileName string) (string, error)

	// AppServerUpserter is used to upsert AppServers.
	AppServerUpserter AppServerUpserter

	// AppServerExpirationDuration is the duration for which the AppServers are valid.
	// Default is two times the SyncPollInterval.
	// Must be greater than SyncPollInterval.
	AppServerExpirationDuration time.Duration

	appServerExpirationFn func() *time.Time
}

func (p *AWSRolesAnywherProfileSyncerParams) checkAndSetDefaults() error {
	if p.SubjectName == "" {
		return trace.BadParameter("subject name is required")
	}

	if p.KeyStoreManager == nil {
		return trace.BadParameter("key store manager is required")
	}

	if p.Cache == nil {
		return trace.BadParameter("cache client is required")
	}

	if p.IntegrationLister == nil {
		return trace.BadParameter("integration lister is required")
	}

	if p.AppServerUpserter == nil {
		return trace.BadParameter("app server upserter is required")
	}

	if p.AppServerPublicURLFn == nil {
		return trace.BadParameter("app server public URL function is required")
	}

	if p.SyncPollInterval == 0 {
		p.SyncPollInterval = time.Second * 10
	}

	if p.AppServerExpirationDuration == 0 {
		p.AppServerExpirationDuration = p.SyncPollInterval * 2
	}

	if p.AppServerExpirationDuration < p.SyncPollInterval {
		return trace.BadParameter("app server expiration duration must be greater than sync poll interval")
	}

	if p.Logger == nil {
		p.Logger = slog.Default()
	}

	if p.Clock == nil {
		p.Clock = clockwork.NewRealClock()
	}

	if p.HostUUID == "" {
		p.HostUUID = uuid.NewString()
	}

	p.appServerExpirationFn = func() *time.Time {
		expires := p.Clock.Now().Add(p.AppServerExpirationDuration)
		return &expires
	}

	return nil
}

// IntegrationLister implements the required methods to list integrations.
type IntegrationLister interface {
	// ListIntegrations returns a paginated list of all integration resources.
	ListIntegrations(ctx context.Context, pageSize int, nextKey string) ([]types.Integration, string, error)
}

type AppServerUpserter interface {
	// UpsertApplicationServer ...
	UpsertApplicationServer(ctx context.Context, server types.AppServer) (*types.KeepAlive, error)
}

// StartAWSRolesAnywherProfileSyncer starts the AWS Roles Anywhere Profile Syncer.
// It will iterate over all AWS Roles Anywhere integrations, and for each one:
// 1. Check if the Profile Sync is enabled.
// 2. Generate AWS credentials using the integration.
// 3. List all profiles in the AWS Roles Anywhere service.
// 4. For each profile, check if it is enabled and has role ARNs.
// 5. Create an AppServer for each profile, using the profile name as the AppServer name.
func StartAWSRolesAnywherProfileSyncer(ctx context.Context, params AWSRolesAnywherProfileSyncerParams) error {
	if err := params.checkAndSetDefaults(); err != nil {
		return trace.Wrap(err)
	}

	for {
		select {
		case <-ctx.Done():
			return nil

		case <-time.After(params.SyncPollInterval):
		}

		integrations, err := integrationsWithProfileSyncEnabled(ctx, params.IntegrationLister)
		if err != nil {
			params.Logger.ErrorContext(ctx, "failed to list integrations", "error", err)
			continue
		}

		for _, integration := range integrations {
			if err := syncProfileForIntegration(ctx, params, integration); err != nil {
				params.Logger.ErrorContext(ctx, "failed to sync AWS Roles Anywhere Profiles for integration", "error", err)
			}
		}
	}
}

func integrationsWithProfileSyncEnabled(ctx context.Context, integrationListerClient IntegrationLister) ([]types.Integration, error) {
	var integrations []types.Integration
	var nextKey string

	for {
		resp, respNextKey, err := integrationListerClient.ListIntegrations(ctx, 0, nextKey)
		if err != nil {
			return nil, trace.Wrap(err)
		}

		for _, integration := range resp {
			if integration.GetSubKind() != types.IntegrationSubKindAWSRolesAnywhere ||
				integration.GetAWSRolesAnywhereIntegrationSpec().ProfileSyncConfig == nil ||
				!integration.GetAWSRolesAnywhereIntegrationSpec().ProfileSyncConfig.Enabled {

				continue
			}

			integrations = append(integrations, integration)
		}

		if respNextKey == "" {
			break
		}
		nextKey = respNextKey
	}

	return integrations, nil
}

func syncProfileForIntegration(ctx context.Context, params AWSRolesAnywherProfileSyncerParams, integration types.Integration) error {
	logger := params.Logger.With("integration", integration.GetName())

	trustAnchorARN := integration.GetAWSRolesAnywhereIntegrationSpec().TrustAnchorARN
	profileSyncProfileARN := integration.GetAWSRolesAnywhereIntegrationSpec().ProfileSyncConfig.ProfileARN
	profileSyncRoleARN := integration.GetAWSRolesAnywhereIntegrationSpec().ProfileSyncConfig.RoleARN
	profileAcceptsRoleSessionName := integration.GetAWSRolesAnywhereIntegrationSpec().ProfileSyncConfig.ProfileAcceptsRoleSessionName

	parsedProfileSyncProfile, err := arn.Parse(profileSyncProfileARN)
	if err != nil {
		return trace.Wrap(err)
	}
	region := parsedProfileSyncProfile.Region

	resp, err := GenerateCredentials(ctx, GenerateCredentialsRequest{
		Clock:                 params.Clock,
		TrustAnchorARN:        trustAnchorARN,
		ProfileARN:            profileSyncProfileARN,
		RoleARN:               profileSyncRoleARN,
		SubjectCommonName:     params.SubjectName,
		AcceptRoleSessionName: profileAcceptsRoleSessionName,
		KeyStoreManager:       params.KeyStoreManager,
		Cache:                 params.Cache,
	})
	if err != nil {
		return trace.Wrap(err)
	}

	awsConfig, err := config.LoadDefaultConfig(
		ctx,
		config.WithRegion(region),
		config.WithCredentialsProvider(credentials.NewStaticCredentialsProvider(resp.AccessKeyID, resp.SecretAccessKey, resp.SessionToken)),
	)
	if err != nil {
		return trace.Wrap(err)
	}

	rolesanywhereClient := rolesanywhere.NewFromConfig(awsConfig)

	var nextPage *string
	for {
		profilesListResp, err := rolesanywhereClient.ListProfiles(ctx, &rolesanywhere.ListProfilesInput{
			NextToken: nextPage,
		})
		if err != nil {
			return trace.Wrap(err)
		}

		for _, profile := range profilesListResp.Profiles {
			logger = logger.With("profile_arn", aws.ToString(profile.ProfileArn), "profile_name", aws.ToString(profile.Name))

			if aws.ToString(profile.ProfileArn) == profileSyncProfileARN {
				logger.DebugContext(ctx, "skipping sync profile")
				continue
			}

			if !aws.ToBool(profile.Enabled) {
				logger.DebugContext(ctx, "Skipping disabled Profile")
				continue
			}

			profileTags, err := rolesanywhereClient.ListTagsForResource(ctx, &rolesanywhere.ListTagsForResourceInput{
				ResourceArn: profile.ProfileArn,
			})
			if err != nil {
				return trace.Wrap(err)
			}

			appServer, err := convertProfile(params, profile, integration.GetName(), profileTags.Tags)
			if err != nil {
				logger.WarnContext(ctx, "failed to convert Profile to AppServer", "error", err)
				continue
			}

			if _, err := params.AppServerUpserter.UpsertApplicationServer(ctx, appServer); err != nil {
				logger.WarnContext(ctx, "failed to UpsertApplicationServer", "error", err)
				continue
			}
		}

		if aws.ToString(profilesListResp.NextToken) == "" {
			break
		}
		nextPage = profilesListResp.NextToken
	}

	return nil
}

func convertProfile(params AWSRolesAnywherProfileSyncerParams, profile ratypes.ProfileDetail, integrationName string, profileTags []ratypes.Tag) (types.AppServer, error) {
	labels := make(map[string]string, len(profileTags))
	// TODO(marco): add integration name to the labels (origin maybe?)
	for _, tag := range profileTags {
		labels["aws/"+aws.ToString(tag.Key)] = aws.ToString(tag.Value)
	}

	appURL, err := params.AppServerPublicURLFn(aws.ToString(profile.Name))
	if err != nil {
		return nil, trace.Wrap(err)
	}

	appServer, err := types.NewAppServerForAWSOIDCIntegration(*profile.Name, params.HostUUID, appURL, labels)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	appServer.Metadata.Expires = params.appServerExpirationFn()
	appServer.Spec.App.Spec.Integration = integrationName
	appServer.Spec.App.Spec.AWS = &types.AppAWS{
		RolesAnywhereProfile: &types.AppAWSRolesAnywhereProfile{
			ProfileARN:            aws.ToString(profile.ProfileArn),
			AcceptRoleSessionName: aws.ToBool(profile.AcceptRoleSessionName),
		},
	}

	return appServer, nil
}
