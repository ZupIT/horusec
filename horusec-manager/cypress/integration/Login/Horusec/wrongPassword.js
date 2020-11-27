/* eslint-disable cypress/no-unnecessary-waiting */
describe('Show the message of invalid password when enter a invlaid password ou username.', () => {
  beforeEach(() => {
    cy.restoreLocalStorage();

    cy.setHorusecAuthConfig();

    cy.intercept(
      {
        method: 'POST',
        url: 'api/auth/authenticate',
      },
      { fixture: 'login/horusec/wrong-password', statusCode: 403 }
    ).as('authenticate');
  });

  afterEach(() => {
    cy.saveLocalStorage();
  });

  it('Fill login form and login.', () => {
    cy.visit('/');
    cy.wait(4200);

    cy.get('#email').click().type('admin@horusec.com');
    cy.get('#password').click().type('secret');
    cy.get('#submit-login').click();

    cy.wait('@authenticate');

    cy.get('#flash-message').should('be.visible');
    cy.get('#flash-message').should(
      'contain.text',
      'Check your e-mail and password and try again.'
    );
  });
});
