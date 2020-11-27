/* eslint-disable cypress/no-unnecessary-waiting */
describe('Validation the field of login form.', () => {
  beforeEach(() => {
    cy.intercept(
      {
        method: 'GET',
        url: 'api/auth/config',
      },
      { fixture: 'auth-config.json', statusCode: 200 }
    ).as('getAuthConfig');
  });

  it('Go to login page.', () => {
    cy.visit('/');
    cy.wait('@getAuthConfig');
  });

  it('Check rendering fields.', () => {
    cy.wait(4200);
    cy.get('#email').should('be.visible');
    cy.get('#password').should('be.visible');
  });

  it('Check if show error message of invalid email.', () => {
    cy.get('#email').click({ force: true }).type('invalidemail@');
    cy.get('#email-error').contains('Invalid e-mail');
  });

  it('Check if show error message of empty password', () => {
    cy.get('#password').click({ force: true }).type('teste').clear().blur();
    cy.get('#password-error').contains('Enter password');
  });

  it('Check if submit button is disabled.', () => {
    cy.get('#submit-login').should('be.disabled');
  });

  it('Submit a valid values', () => {
    cy.get('#email').clear().click({ force: true }).type('email@email.com');
    cy.get('#password').click({ force: true }).type('mypassword');
    cy.get('#submit-login').should('be.enabled');
  });
});
