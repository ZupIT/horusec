import ptBR from '../../../src/config/i18n/ptBR.json';
import enUS from '../../../src/config/i18n/enUS.json';

/* eslint-disable cypress/no-unnecessary-waiting */
describe('Login in the application when a correct username and password.', () => {
  beforeEach(() => {
    cy.restoreLocalStorage();
    cy.setHorusecAuthConfig();
  });

  afterEach(() => {
    cy.saveLocalStorage();
  });

  it('Change language to ptBR', () => {
    cy.visit('/');

    cy.wait(4200);

    cy.get('#submit-login').should('contain.text', enUS.LOGIN_SCREEN.SUBMIT);

    cy.get('#language').click();
    cy.get('#ptBR').click();

    cy.get('#submit-login').should('contain.text', ptBR.LOGIN_SCREEN.SUBMIT);

    cy.get('#language').click();
    cy.get('#enUS').click();

    cy.get('#submit-login').should('contain.text', enUS.LOGIN_SCREEN.SUBMIT);
  });
});
