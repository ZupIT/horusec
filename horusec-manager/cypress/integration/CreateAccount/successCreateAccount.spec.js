import { CREATE_ACCOUNT_SCREEN } from '../../../src/config/i18n/enUS.json';

/* eslint-disable cypress/no-unnecessary-waiting */
describe('Validation the field of login create account form.', () => {
  beforeEach(() => {
    cy.setHorusecAuthConfig();

    cy.intercept(
      {
        method: 'POST',
        url: 'auth/account/verify-already-used',
      },
      { fixture: 'createAccount/verifyAlreadyUsed/success', statusCode: 200 }
    ).as('verifyAlreadyUsed');

    cy.intercept(
      {
        method: 'POST',
        url: 'auth/account/create-account',
      },
      { fixture: 'createAccount/success', statusCode: 201 }
    ).as('createAccount');
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

  it('Fill user info and go to next step', () => {
    cy.get('#username').click().type('myusername');
    cy.get('#email').click().type('email@email.com');

    cy.get('#next-step').click();
  });

  it('Fill the password', () => {
    cy.get('#password').click().type('My*Pass123');
    cy.get('#confirm-pass').click().type('My*Pass123');

    cy.get('#register').click();

    cy.wait('@createAccount');
  });

  it('Check success message in dialog', () => {
    cy.get('#message-dialog').should(
      'contain.text',
      CREATE_ACCOUNT_SCREEN.SUCCESS_CREATE_ACCOUNT
    );
  });
});
