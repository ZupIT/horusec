import { CREATE_ACCOUNT_SCREEN } from '../../../src/config/i18n/enUS.json';

/* eslint-disable cypress/no-unnecessary-waiting */
describe('Validation the field of login create account form.', () => {
  beforeEach(() => {
    cy.setHorusecAuthConfig();

    cy.intercept(
      {
        method: 'POST',
        url: 'api/account/verify-already-used',
      },
      { fixture: 'createAccount/verifyAlreadyUsed/success', statusCode: 200 }
    ).as('verifyAlreadyUsed');
  });

  it('Check rendering button to register', () => {
    cy.visit('/');
    cy.wait(4200);

    cy.get('#create-account').should('be.visible');
    cy.get('#create-account').click();
  });

  it('Check if navigate to the create account screen.', () => {
    cy.get('h2').should('contain.text', CREATE_ACCOUNT_SCREEN.CREATE_ACCOUNT);
  });

  it('Fill the fields with invalid data.', () => {
    cy.get('#username').click().type('testing');
    cy.get('#email').click().type('invalidemail@');
  });

  it('Check message of invalid email', () => {
    cy.get('#email-error').should('be.visible');
    cy.get('#email-error').should(
      'contain.text',
      CREATE_ACCOUNT_SCREEN.INVALID_EMAIL
    );
  });

  it('Check message of invalid name', () => {
    cy.get('#username').click().clear();
    cy.get('#username-error').should('be.visible');
    cy.get('#username-error').should(
      'contain.text',
      CREATE_ACCOUNT_SCREEN.INVALID_NAME
    );
  });

  it('Go to next step', () => {
    cy.get('#username').click().type('username');
    cy.get('#email').click().clear();
    cy.get('#email').click().type('email@email.com');
    cy.get('#next-step').click();

    cy.wait('@verifyAlreadyUsed');

    cy.get('#password').should('be.visible');
    cy.get('#register').should('be.disabled');
  });

  it('Fill fields and check message error of password', () => {
    cy.get('#password').click().type('invalidPassword');
    cy.get('#confirm-pass').click().type('invalidConfirmPassword');

    cy.get('#confirm-pass-error').should('be.visible');
    cy.get('#confirm-pass-error').should(
      'contain.text',
      CREATE_ACCOUNT_SCREEN.INVALID_CONFIRM_PASS
    );

    cy.get('#password').click().clear();

    cy.get('#password-error').should('be.visible');
    cy.get('#password-error').should(
      'contain.text',
      CREATE_ACCOUNT_SCREEN.INVALID_PASS
    );

    cy.get('#register').should('be.disabled');
  });
});
