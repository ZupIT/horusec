describe("Login", () => {
    beforeEach(() => {
        cy.visit("https://manager.horus.dev.zup.corp/auth");
    });

    it("Should login with default account", () => {
        cy.get("#email").type("dev@example.com");
        cy.get("#password").type("Devpass0*");
        cy.get("button").first().click();
    });
});
