/**
 * Teleport
 * Copyright (C) 2023  Gravitational, Inc.
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

import React from 'react';

import { Alert, Box, Flex, Mark, Text } from 'design';
import FieldInput from 'shared/components/FieldInput';
import Validation from 'shared/components/Validation';

import { requiredAwsIdentityCenterRegion } from 'e-teleport/Integrations/IntegrationEnroll/PluginEnroll/MultiStep/AwsIdentityCenter/rules';
import { Header } from 'teleport/Discover/Shared';
import { StyledBox } from 'teleport/Discover/Shared/StyledBox';

export function AwsConsole() {
  // const {
  //   integrationConfig,
  //   setIntegrationConfig,
  //   scriptUrl,
  //   setScriptUrl,
  //   handleOnCreate,
  //   createdIntegration,
  //   createIntegrationAttempt,
  //   generateAwsOidcConfigIdpScript,
  // } = useAwsOidcIntegration();
  // const { clusterId } = useStickyClusterId();

  return (
    <Box pt={3}>
      <Header>AWS CLI / Console Access</Header>
      <Box width="800px" mb={4}>
        Compatible with any CLI and AWS SDK-based tootling (includes Terraform,
        AWS CLI). Teleport uses AWS IAM Roles Anywhere to manage access and
        allows you to configure the right permissions for your users.
        <br />
        Follow the below steps to create a Roles Anywhere Trust Anchor and
        configure the required IAM Roles for synchronizing Profiles as Teleport
        resources.
        <Alert
          kind="info"
          mt={5}
          details={
            'Create Profiles and assign Roles to them in your AWS account. Teleport will allow you to import these Profiles as Resources.'
          }
        >
          Prerequisites
          {/*  todo mberg button */}
        </Alert>
      </Box>
      <Validation>
        {({ validator }) => (
          <StyledBox mb={4}>
            <Text bold>Step 1: Name your Teleport Integration</Text>
            <Text mt={1} mb={4}>
              Give this integration a name.
            </Text>
            <Flex flexDirection="column" gap={1} mb={4} maxWidth={500}>
              <FieldInput
                label="Integration Name*"
                placeholder="MyIntegrationName"
              />
            </Flex>
          </StyledBox>
        )}
      </Validation>
    </Box>
  );
}
