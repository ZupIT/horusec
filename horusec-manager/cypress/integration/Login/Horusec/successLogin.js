/* eslint-disable cypress/no-unnecessary-waiting */
describe('Login in the application when a correct username and password.', () => {
  beforeEach(() => {
    cy.restoreLocalStorage();

    cy.setHorusecAuthConfig();

    cy.intercept(
      {
        method: 'POST',
        url: 'api/auth/authenticate',
      },
      { fixture: 'login/horusec/success', statusCode: 200 }
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

    cy.get('h1').should('contain.text', 'Select an organization');
  });
});
