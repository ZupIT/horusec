import { Requests } from "../../utils/request";
import AnalysisMock from "../../mocks/analysis.json";

describe("Horusec tests", () => {
    beforeEach(() => {
        cy.exec("cd ../../ && make migrate-drop", {log: true});
        cy.exec("cd ../../ && make migrate", {log: true});
    });

    it("Should test all operations horusec", () => {
        LoginWithDefaultAccountAndCheckIfNotExistWorkspace();
        CreateEditDeleteAnWorkspace();
        CreateWorkspace("My company");
        CheckIfDashboardIsEmpty();
        CreateDeleteWorkspaceTokenAndSendFirstAnalysisMock();
        CheckIfDashboardNotIsEmpty();
        CreateEditDeleteAnRepository();
        CreateRepository("Core-API");
        CreateDeleteRepositoryTokenAndSendFirstAnalysisMock("Core-API");
        CheckIfDashboardNotIsEmptyWithTwoRepositories("Core-API");
        CheckIfExistsVulnerabilitiesAndCanUpdateSeverityAndStatus();
        UpdateAndDeleteAccountLoggedUser();
    });
});

function CreateEditDeleteAnWorkspace(): void {
    cy.wait(1500);
    createFirstWorkspace();
    cy.wait(300);
    editCurrentWorkspace();
    cy.wait(300);
    deleteCurrentWorkspace();
}

function CreateDeleteWorkspaceTokenAndSendFirstAnalysisMock(): void {
    cy.get("div").contains("Manage Workspaces").parent().parent().click();
    cy.get("div").contains("Manage Workspaces").click();
    cy.window().then(win => {
        cy.stub(win, "prompt").returns("DISABLED WINDOW PROMPT");
    });
    cy.get("button").contains("Tokens").click();
    cy.wait(300);
    cy.get("button").contains("Add Token").click();
    cy.wait(300);
    cy.get("#description").type("Access Token");
    cy.get("button").contains("Save").click();
    cy.get("[data-testid=\"icon-copy\"").click();
    cy.get("h3").first().then(async (content) => {
        const _requests: Requests = new Requests();
        const body: any = AnalysisMock;
        const url: any = `${_requests.baseURL}${_requests.services.Api}/api/analysis`;
        const response: any = await _requests.setAuthorization(content[0].innerText).post(url, body);
        expect(response.status).eq(201, "First Analysis of workspace created with sucess");
    });
    cy.get("button").contains("Ok, I got it.").click();
    cy.contains("Access Token").should("exist");
    cy.wait(1000);
    cy.get("button").contains("Add Token").parent().parent().contains("Delete").click();
    cy.wait(300);
    cy.get("button").contains("Yes").click();
    cy.contains("Access Token").should("not.exist");
}

function LoginWithDefaultAccountAndCheckIfNotExistWorkspace(): void {
    cy.visit("http://localhost:8043/auth");
    cy.wait(4000);
    cy.get("#email").type("dev@example.com");
    cy.get("#password").type("Devpass0*");
    cy.get("button").first().click();
    cy.wait(1000);
    cy.contains("Add a new Workspace to start using Horusec.").should("exist");
}

function createFirstWorkspace(): void {
    cy.get("button").contains("Add workspace").click();
    cy.wait(300);
    cy.get("button").contains("Add Workspace").click();
    cy.wait(300);
    cy.get("#name").type("first_workspace");
    cy.get("button").contains("Save").click();
    cy.contains("first_workspace").should("exist");
}

function editCurrentWorkspace(): void {
    cy.get("button").contains("Edit").click();
    cy.wait(300);
    cy.get("#name").type("_edited");
    cy.get("button").contains("Save").click();
    cy.contains("first_workspace_edited").should("exist");
}

function deleteCurrentWorkspace(): void {
    cy.get("button").contains("Delete").click();
    cy.wait(300);
    cy.get("button").contains("Yes").click();
    cy.contains("first_workspace_edited").should("not.exist");
}

function CreateWorkspace(workspaceName: string): void {
    cy.get("button").contains("Add Workspace").click();
    cy.wait(300);
    cy.get("#name").type(workspaceName);
    cy.get("button").contains("Save").click();
    cy.contains(workspaceName).should("exist");
}

function CheckIfDashboardIsEmpty(): void {
    cy.visit("http://localhost:8043/home/dashboard/repositories");
    cy.wait(1000);
    cy.get("button").contains("Apply").click();
    cy.wait(3000);
    cy.get("h4").contains("Total developers").parent().contains("1").should("not.exist");
}

function CheckIfDashboardNotIsEmpty(): void {
    cy.visit("http://localhost:8043/home/dashboard/repositories");
    cy.wait(1500);
    cy.get("button").contains("Apply").click();
    cy.get("h4").contains("Total developers").parent().contains("1").should("exist");
    cy.get("h4").contains("All vulnerabilities").parent().contains("CRITICAL").should("exist");
    cy.get("h4").contains("All vulnerabilities").parent().contains("HIGH").should("exist");
    cy.get("h4").contains("All vulnerabilities").parent().contains("INFO").should("exist");
    cy.get("h4").contains("All vulnerabilities").parent().contains("LOW").should("exist");
    cy.get("h4").contains("All vulnerabilities").parent().contains("MEDIUM").should("exist");
    cy.get("h4").contains("All vulnerabilities").parent().contains("UNKNOWN").should("exist");
    cy.get("span").contains("Dashboard").parent().click();
    cy.get("[data-testid=\"icon-grid\"").parent().click();
    cy.wait(3000);
    cy.get("h4").contains("Vulnerabilities by repository").parent().contains("17").should("exist");
    cy.get("h4").contains("Vulnerabilities by repository").parent().contains("57").should("exist");
    cy.get("h4").contains("Vulnerabilities by repository").parent().contains("29").should("exist");
    cy.get("h4").contains("Vulnerabilities by repository").parent().contains("45").should("exist");
    cy.get("h4").contains("Vulnerabilities by repository").parent().contains("16").should("exist");
    cy.get("h4").contains("Vulnerabilities by repository").parent().contains("13").should("exist");
}

function CreateEditDeleteAnRepository(): void {
    cy.get("span").contains("Repositories").parent().click();
    cy.wait(1500);
    createFirstRepository();
    cy.wait(300);
    editCurrentRepository();
    cy.wait(300);
    deleteCurrentRepository();
}

function createFirstRepository(): void {
    cy.get("button").contains("Create repository").click();
    cy.wait(300);
    cy.get("#name").type("first_repository");
    cy.get("button").contains("Save").click();
    cy.contains("first_repository").should("exist");
}

function editCurrentRepository(): void {
    cy.get("td").contains("first_repository").parent().contains("Edit").click();
    cy.wait(300);
    cy.get("#name").type("_edited");
    cy.get("button").contains("Save").click();
    cy.contains("first_repository_edited").should("exist");
}

function deleteCurrentRepository(): void {
    cy.get("td").contains("first_repository_edited").parent().contains("Delete").click();
    cy.wait(300);
    cy.get("button").contains("Yes").click();
    cy.contains("first_repository_edited").should("not.exist");
}

function CreateRepository(repositoryName: string): void {
    cy.get("button").contains("Create repository").click();
    cy.wait(300);
    cy.get("#name").type(repositoryName);
    cy.get("button").contains("Save").click();
    cy.contains(repositoryName).should("exist");
}

function CreateDeleteRepositoryTokenAndSendFirstAnalysisMock(repositoryName: string): void {
    cy.window().then(win => {
        cy.stub(win, "prompt").returns("DISABLED WINDOW PROMPT");
    });
    cy.get("td").contains(repositoryName).parent().contains("Tokens").click();
    cy.wait(300);
    cy.get("button").contains("Add Token").click();
    cy.wait(300);
    cy.get("#description").type("Access Token");
    cy.get("button").contains("Save").click();
    cy.get("[data-testid=\"icon-copy\"").click();
    cy.get("h3").first().then(async (content) => {
        const _requests: Requests = new Requests();
        const body: any = AnalysisMock;
        body.repositoryName = repositoryName;
        body.analysis.id = "802e0032-e173-4eb6-87b1-8a6a3d674503";
        const url: any = `${_requests.baseURL}${_requests.services.Api}/api/analysis`;
        const response: any = await _requests.setAuthorization(content[0].innerText).post(url, body);
        expect(response.status).eq(201, "First Analysis of repository created with sucess");
    });
    cy.get("button").contains("Ok, I got it.").click();
    cy.contains("Access Token").should("exist");
    cy.wait(1000);
    cy.get("button").contains("Add Token").parent().parent().contains("Delete").click();
    cy.wait(300);
    cy.get("button").contains("Yes").click();
    cy.contains("Access Token").should("not.exist");
}

function CheckIfDashboardNotIsEmptyWithTwoRepositories(repositoryName: string): void {
    cy.visit("http://localhost:8043/home/dashboard/repositories");
    cy.wait(3000);
    cy.get("div").contains(repositoryName).parent().parent().click();
    cy.get("div").contains(repositoryName).click();
    cy.get("button").contains("Apply").click();
    cy.wait(1500);
    cy.get("h4").contains("Total developers").parent().contains("1").should("exist");
    cy.get("h4").contains("All vulnerabilities").parent().contains("CRITICAL").should("exist");
    cy.get("h4").contains("All vulnerabilities").parent().contains("HIGH").should("exist");
    cy.get("h4").contains("All vulnerabilities").parent().contains("INFO").should("exist");
    cy.get("h4").contains("All vulnerabilities").parent().contains("LOW").should("exist");
    cy.get("h4").contains("All vulnerabilities").parent().contains("MEDIUM").should("exist");
    cy.get("h4").contains("All vulnerabilities").parent().contains("UNKNOWN").should("exist");
    cy.get("h4").contains("Vulnerabilities by developer").parent().contains("17").should("exist");
    cy.get("h4").contains("Vulnerabilities by developer").parent().contains("57").should("exist");
    cy.get("h4").contains("Vulnerabilities by developer").parent().contains("29").should("exist");
    cy.get("h4").contains("Vulnerabilities by developer").parent().contains("45").should("exist");
    cy.get("h4").contains("Vulnerabilities by developer").parent().contains("16").should("exist");
    cy.get("h4").contains("Vulnerabilities by developer").parent().contains("13").should("exist");
}
function CheckIfExistsVulnerabilitiesAndCanUpdateSeverityAndStatus(): void {
    cy.get("[data-testid=\"icon-shield\"").parent().click();
    cy.wait(1500);
    cy.get("tr>td").eq(2).children().children().click();
    cy.wait(300);
    cy.get("tr>td").eq(2).contains("HIGH").click();
    cy.contains("Vulnerability status successfully changed!").should("exist");
    cy.wait(4000);
    cy.get("tr>td").eq(3).children().children().click();
    cy.get("tr>td").eq(3).contains("Risk Accepted").click();
    cy.contains("Vulnerability status successfully changed!").should("exist");
    cy.get("tr>td").eq(4).children().children().click();
    cy.wait(300);
    cy.contains("Vulnerability Details").should("exist");
}

function UpdateAndDeleteAccountLoggedUser(): void {
    cy.get("[data-testid=\"icon-config\"").click();
    cy.wait(1500);
    cy.get("button").contains("Edit").click();
    cy.get("#nome").clear().type("user_updated");
    cy.get("#email").clear().type("user_updated@example.com");
    cy.get("button").contains("Save").click();
    cy.contains("user_updated").should("exist");
    cy.contains("user_updated@example.com").should("exist");
    cy.get("[data-testid=\"icon-logout\"").click();
    cy.wait(4000);
    cy.get("#email").type("user_updated@example.com");
    cy.get("#password").type("Devpass0*");
    cy.get("button").first().click();
    cy.wait(1500);
    cy.get("[data-testid=\"icon-config\"").click();
    cy.wait(1500);
    cy.get("button").contains("Password").click();
    cy.get("#password").clear().type("Ch@ng3m3");
    cy.get("#confirm-pass").clear().type("Ch@ng3m3");
    cy.get("button").contains("Save").click();
    cy.get("[data-testid=\"icon-logout\"").click();
    cy.wait(4000);
    cy.get("#email").type("user_updated@example.com");
    cy.get("#password").type("Ch@ng3m3");
    cy.get("button").first().click();
    cy.wait(1500);
    cy.contains("Version").should("exist");
    cy.get("[data-testid=\"icon-config\"").click();
    cy.wait(1500);
    cy.get("button").contains("Delete").click();
    cy.get("button").contains("Yes").click();
}

