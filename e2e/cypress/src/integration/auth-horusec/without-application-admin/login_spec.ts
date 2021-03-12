describe("Login", () => {
    beforeEach(() => {
        cy.visit("https://manager.horus.dev.zup.corp/auth");
    });

    it("Should login with default account", () => {
        cy.get("#email").type("dev@examples.com");
        cy.get("#password").type("Devpass0*");
        cy.get("button").click();
    });
});
