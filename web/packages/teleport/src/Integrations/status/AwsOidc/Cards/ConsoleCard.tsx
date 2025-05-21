import { H2 } from '@storybook/components';
import * as Icons from 'web/packages/design/src/Icon';

import Box from 'design/Box';
import { CardTile } from 'design/CardTile';
import Flex from 'design/Flex';
import { H3, P2 } from 'design/Text';

export function ConsoleCard() {
  return <ConsoleEnrollCard />;
}

function ConsoleEnrollCard() {
  return (
    <CardTile width="100%" data-testid={`console-enroll`}>
      <Flex flexDirection="column" justifyContent="space-between" height="100%">
        <Box>
          <Flex alignItems="center">
            <H2>AWS Console and CLI Access</H2>
          </Flex>
          <P2 mb={2}>
            {/*todo mberg copy*/}
            Allows to create new app resources, to access AWS account.
          </P2>
        </Box>
        <Flex alignItems="center" gap={2}>
          <H3>Enable Access</H3>
          <Icons.ArrowForward />
        </Flex>
      </Flex>
    </CardTile>
  );
}
