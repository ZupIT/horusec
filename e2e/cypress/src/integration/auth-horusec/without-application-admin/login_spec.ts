describe("Login", () => {
    beforeEach(() => {
        cy.visit("https://localhost:8043");
    });

    it("Should login with default account", () => {
        cy.wait(2000)
        cy.get("#email").type("dev@example.com");
        cy.get("#password").type("Devpass0*");
        cy.get("button").first().click();
    });
});
