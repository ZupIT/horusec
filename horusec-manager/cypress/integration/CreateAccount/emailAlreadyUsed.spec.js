import { API_ERRORS } from '../../../src/config/i18n/enUS.json';

/* eslint-disable cypress/no-unnecessary-waiting */
describe('Validation the field of login create account form.', () => {
  beforeEach(() => {
    cy.setHorusecAuthConfig();

    cy.intercept(
      {
        method: 'POST',
        url: 'api/account/verify-already-used',
      },
      { fixture: 'createAccount/verifyAlreadyUsed/error', statusCode: 400 }
    ).as('verifyAlreadyUsed');
  });

  it('Go to register screen', () => {
    cy.visit('/');
    cy.wait(4200);

    cy.get('#create-account').should('be.visible');
    cy.get('#create-account').click();
  });

  it('Fill the fields and submit', () => {
    cy.get('#username').click().type('testing');
    cy.get('#email').click().type('test@test.com');

    cy.get('#next-step').click();

    cy.wait('@verifyAlreadyUsed');
  });

  it('Check the flash message error', () => {
    cy.get('#flash-message-error').should('be.visible');
    cy.get('#flash-message-error').should(
      'contain.text',
      API_ERRORS.EMAIL_IN_USE
    );
  });
});
