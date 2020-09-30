import React, { useState } from 'react';
import { CreateAccounteProvider } from 'contexts/CreateAccount';
import ExternalLayout from 'layouts/External';

import UserInfoForm from './UserInfo';
import PasswordForm from './Password';

function CreateAccountScreen() {
  const [showUserInfoStep, setShowUserInfoStep] = useState(true);

  return (
    <CreateAccounteProvider>
      <ExternalLayout>
        {showUserInfoStep ? (
          <UserInfoForm onNextStep={() => setShowUserInfoStep(false)} />
        ) : (
          <PasswordForm />
        )}
      </ExternalLayout>
    </CreateAccounteProvider>
  );
}

export default CreateAccountScreen;
