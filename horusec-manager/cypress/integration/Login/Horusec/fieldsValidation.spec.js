import { LOGIN_SCREEN } from '../../../../src/config/i18n/enUS.json';

/* eslint-disable cypress/no-unnecessary-waiting */
describe('Validation the field of login form.', () => {
  beforeEach(() => {
    cy.setHorusecAuthConfig();
  });

  it('Check rendering fields.', () => {
    cy.visit('/');
    cy.wait(4200);

    cy.get('#email').should('be.visible');
    cy.get('#password').should('be.visible');
  });

  it('Check if show error message of invalid email.', () => {
    cy.get('#email').click().type('invalidemail@');
    cy.get('#email-error').should('contain.text', LOGIN_SCREEN.INVALID_EMAIL);
  });

  it('Turn visible password.', () => {
    cy.get('#password').should('have.attr', 'type', 'password');
    cy.get('#icon-view').click();
    cy.get('#password').should('have.attr', 'type', 'text');
    cy.get('#icon-no-view').click();
  });

  it('Check if show error message of empty password', () => {
    cy.get('#password').click().type('test').clear().blur();
    cy.get('#password-error').should('contain.text', LOGIN_SCREEN.INVALID_PASS);
  });

  it('Check if submit button is disabled.', () => {
    cy.get('#submit-login').should('have.attr', 'aria-disabled');
  });

  it('Submit a valid values', () => {
    cy.get('#email').clear().click().type('email@email.com');
    cy.get('#password').click().type('mypassword');
    cy.get('#submit-login').should('be.enabled');
  });
});
