import { Requests } from "../../utils/request";
import AnalysisMock from "../../mocks/analysis.json";

describe("Horusec tests", () => {
    before(() => {
        cy.exec("cd ../../ && make e2e-migrate", {log: true}).its("code").should("eq", 0);
    });

    it("Should test all operations horusec", () => {
        CreateDefaultAccount();
        LoginWithDefaultAccountAndCheckIfNotExistWorkspace();
        CreateEditDeleteAnWorkspace();
        CreateWorkspace("Company e2e");
        CheckIfDashboardIsEmpty();
        CreateDeleteWorkspaceTokenAndSendFirstAnalysisMock();
        CheckIfDashboardNotIsEmpty();
        CreateEditDeleteAnRepository();
        CreateRepository("Core-API");
        CreateDeleteRepositoryTokenAndSendFirstAnalysisMock("Core-API");
        CheckIfDashboardNotIsEmptyWithTwoRepositories("Core-API");
        CheckIfExistsVulnerabilitiesAndCanUpdateSeverityAndStatus();
        CreateUserAndInviteToExistingWorkspace();
        CheckIfPermissionsIsEnableToWorkspaceMember();
        InviteUserToRepositoryAndCheckPermissions("Core-API");
        LoginAndUpdateDeleteAccount();
    });
});

function CreateDefaultAccount(): void {
    cy.visit("http://localhost:8043/auth");
    cy.wait(4000);

    // Create default account
    cy.get("button").contains("Don't have an account? Sign up").click();
    cy.get("#username").clear().type("dev");
    cy.get("#email").clear().type("dev@example.com");
    cy.get("button").contains("Next").click();
    cy.get("#password").clear().type("Devpass0*");
    cy.get("#confirm-pass").clear().type("Devpass0*");
    cy.get("button").contains("Register").click();

    // Check if account was created
    cy.contains("Your Horusec account has been successfully created!");
    cy.get("button").contains("Ok, I got it.").click();
}

function LoginWithDefaultAccountAndCheckIfNotExistWorkspace(): void {
    // Login with default account
    cy.get("#email").type("dev@example.com");
    cy.get("#password").type("Devpass0*");
    cy.get("button").first().click();
    cy.wait(1000);

    // Check if not exists workspace
    cy.contains("Add a new Workspace to start using Horusec.").should("exist");
}

function CreateEditDeleteAnWorkspace(): void {
    cy.wait(1500);

    // Create an workspace
    cy.get("button").contains("Add workspace").click();
    cy.wait(500);
    cy.get("button").contains("Add Workspace").click();
    cy.wait(500);
    cy.get("#name").type("first_workspace");
    cy.get("button").contains("Save").click();

    // Check if exist on list
    cy.contains("first_workspace").should("exist");
    cy.wait(500);

    // Edit existing workspace
    cy.get("button").contains("Edit").click();
    cy.wait(500);
    cy.get("#name").type("_edited");
    cy.get("button").contains("Save").click();

    // Check if was updated on list
    cy.contains("first_workspace_edited").should("exist");
    cy.wait(500);

    // Delete existing workspace
    cy.get("button").contains("Delete").click();
    cy.wait(500);
    cy.get("button").contains("Yes").click();

    // Check if was removed on list
    cy.contains("first_workspace_edited").should("not.exist");
}

function CreateWorkspace(workspaceName: string): void {
    cy.get("button").contains("Add Workspace").click();
    cy.wait(500);
    cy.get("#name").type(workspaceName);
    cy.get("button").contains("Save").click();

    // Check if exist new workspace on list
    cy.contains(workspaceName).should("exist");
}

function CheckIfDashboardIsEmpty(): void {
    // Go to workspace repositories and check if repositories data is empty
    cy.visit("http://localhost:8043/home/dashboard/repositories");
    cy.wait(4000);
    cy.get("button").contains("Apply").click();
    cy.wait(5000);
    cy.get("h4").contains("Total developers").parent().contains("1").should("not.exist");
}

function CreateDeleteWorkspaceTokenAndSendFirstAnalysisMock(): void {
    // Go to manage workspace page
    cy.get("div").contains("Manage Workspaces").parent().parent().click();
    cy.get("div").contains("Manage Workspaces").click();

    // Disable alert when copy data to clipboard
    cy.window().then(win => {
        cy.stub(win, "prompt").returns("DISABLED WINDOW PROMPT");
    });

    // Create access token
    cy.get("button").contains("Tokens").click();
    cy.wait(500);
    cy.get("button").contains("Add Token").click();
    cy.wait(500);
    cy.get("#description").type("Access Token");
    cy.get("button").contains("Save").click();

    // Copy acceess token to clipboard and create first analysis with this token
    cy.get("[data-testid=\"icon-copy\"").click();
    cy.get("h3").first().then((content) => {
        const _requests: Requests = new Requests();
        const body: any = AnalysisMock;
        const url: any = `${_requests.baseURL}${_requests.services.Api}/api/analysis`;
        _requests
            .setHeadersAllRequests({"X-Horusec-Authorization": content[0].innerText})
            .post(url, body)
            .then((response) => {
                expect(response.status).eq(201, "First Analysis of workspace created with sucess");
            })
            .catch((err) => {
                cy.log("Error on send analysis in token of workspace: ", err).end();
            });
    });
    cy.wait(3000);
    cy.get("button").contains("Ok, I got it.").click();

    // Check if exists access token on list of token
    cy.contains("Access Token").should("exist");
    cy.wait(1000);

    // Remove access token created
    cy.get("button").contains("Add Token").parent().parent().contains("Delete").click();
    cy.wait(500);
    cy.get("button").contains("Yes").click();

    // Check if not exists access token on list of token
    cy.contains("Access Token").should("not.exist");
}

function CheckIfDashboardNotIsEmpty(): void {
    // Go to dashboard page
    cy.visit("http://localhost:8043/home/dashboard/repositories");
    cy.wait(4000);

    // Search from begging data
    cy.get("button").contains("Apply").click();

    // Check if chart of total developers exist 1 user in selected repository
    cy.get("h4").contains("Total developers").parent().contains("1").should("exist");
    // Check if chart with all vulnerabilities of exists all vulnerabilities
    cy.get("h4").contains("All vulnerabilities").parent().contains("CRITICAL").should("exist");
    cy.get("h4").contains("All vulnerabilities").parent().contains("HIGH").should("exist");
    cy.get("h4").contains("All vulnerabilities").parent().contains("INFO").should("exist");
    cy.get("h4").contains("All vulnerabilities").parent().contains("LOW").should("exist");
    cy.get("h4").contains("All vulnerabilities").parent().contains("MEDIUM").should("exist");
    cy.get("h4").contains("All vulnerabilities").parent().contains("UNKNOWN").should("exist");

    // Go to dashboard by workspace visualization
    cy.get("span").contains("Dashboard").parent().click();
    cy.get("[data-testid=\"icon-grid\"").parent().click();
    cy.wait(5000);

    // Check if exists total vulnerabilities in chart of vulnerabilities by repository
    cy.get("h4").contains("Vulnerabilities by repository").parent().contains("17").should("exist");
    cy.get("h4").contains("Vulnerabilities by repository").parent().contains("57").should("exist");
    cy.get("h4").contains("Vulnerabilities by repository").parent().contains("29").should("exist");
    cy.get("h4").contains("Vulnerabilities by repository").parent().contains("45").should("exist");
    cy.get("h4").contains("Vulnerabilities by repository").parent().contains("16").should("exist");
    cy.get("h4").contains("Vulnerabilities by repository").parent().contains("13").should("exist");
}

function CreateEditDeleteAnRepository(): void {
    // Go to repositories page
    cy.get("span").contains("Repositories").parent().click();
    cy.wait(1500);

    // Create an repository
    cy.get("button").contains("Create repository").click();
    cy.wait(500);
    cy.get("#name").type("first_repository");
    cy.get("button").contains("Save").click();

    // Check if this repository exists on list
    cy.contains("first_repository").should("exist");
    cy.wait(1500);

    // Edit the new repository
    cy.get(":nth-child(2) > :nth-child(3) > .row > :nth-child(1)").click();
    cy.wait(500);
    cy.get("#name").type("_edited");
    cy.get("button").contains("Save").click();

    // Check if repository was edited with success
    cy.contains("first_repository_edited").should("exist");
    cy.wait(1500);

    // Delete the repository
    cy.get(":nth-child(2) > :nth-child(3) > .row > :nth-child(2)").click();
    cy.wait(500);
    cy.get("button").contains("Yes").click();
    cy.wait(1000);

    // Check if repository was deleted with success
    cy.contains("first_repository_edited").should("not.exist");
}

function CreateRepository(repositoryName: string): void {
    cy.get("button").contains("Create repository").click();
    cy.wait(500);
    cy.get("#name").type(repositoryName);
    cy.get("button").contains("Save").click();
    cy.contains(repositoryName).should("exist");
}

function CreateDeleteRepositoryTokenAndSendFirstAnalysisMock(repositoryName: string): void {
    cy.wait(1500);
    // Disable alert when copy data to clipboard
    cy.window().then(win => {
        cy.stub(win, "prompt").returns("DISABLED WINDOW PROMPT");
    });

    // Get repository created and create new access token
    cy.get(":nth-child(2) > :nth-child(3) > .row > :nth-child(4)").click();
    cy.wait(500);
    cy.contains("Add Token").should("exist");
    cy.get("button").contains("Add Token").click();
    cy.wait(500);
    cy.get("#description").type("Access Token");
    cy.get("button").contains("Save").click();

    // Copy acceess token to clipboard and create first analysis with this token into repository
    cy.get("[data-testid=\"icon-copy\"").click();
    cy.get("h3").first().then((content) => {
        const _requests: Requests = new Requests();
        const body: any = AnalysisMock;
        body.repositoryName = repositoryName;
        body.analysis.id = "802e0032-e173-4eb6-87b1-8a6a3d674503";
        const url: any = `${_requests.baseURL}${_requests.services.Api}/api/analysis`;
        _requests
            .setHeadersAllRequests({"X-Horusec-Authorization": content[0].innerText})
            .post(url, body)
            .then((response) => {
                expect(response.status).eq(201, "First Analysis of repository created with sucess");
            })
            .catch((err) => {
                cy.log("Error on send analysis in token of repository: ", err).end();
            });
    });
    cy.wait(3000);
    cy.get("button").contains("Ok, I got it.").click();

    // Check if access token exist on list of tokens
    cy.contains("Access Token").should("exist");
    cy.wait(1000);

    // Delete access token
    cy.get("button").contains("Add Token").parent().parent().contains("Delete").click();
    cy.wait(500);
    cy.get("button").contains("Yes").click();

    // Check if access token was deleted
    cy.contains("Access Token").should("not.exist");
}

function CheckIfDashboardNotIsEmptyWithTwoRepositories(repositoryName: string): void {
    // Go to dasboard page
    cy.visit("http://localhost:8043/home/dashboard/repositories");
    cy.wait(4000);
    // Select dashboard by repository created and search
    cy.get("div").contains(repositoryName).parent().parent().click();
    cy.get("div").contains(repositoryName).click();
    cy.get("button").contains("Apply").click();
    cy.wait(1500);

    // Check if chart of total developers exist 1 user in selected repository
    cy.get("h4").contains("Total developers").parent().contains("1").should("exist");
    // Check if chart with all vulnerabilities of exists all vulnerabilities
    cy.get("h4").contains("All vulnerabilities").parent().contains("CRITICAL").should("exist");
    cy.get("h4").contains("All vulnerabilities").parent().contains("HIGH").should("exist");
    cy.get("h4").contains("All vulnerabilities").parent().contains("INFO").should("exist");
    cy.get("h4").contains("All vulnerabilities").parent().contains("LOW").should("exist");
    cy.get("h4").contains("All vulnerabilities").parent().contains("MEDIUM").should("exist");
    cy.get("h4").contains("All vulnerabilities").parent().contains("UNKNOWN").should("exist");
    // Check if exists total vulnerabilities in chart of vulnerability by developer
    cy.get("h4").contains("Vulnerabilities by developer").parent().contains("17").should("exist");
    cy.get("h4").contains("Vulnerabilities by developer").parent().contains("57").should("exist");
    cy.get("h4").contains("Vulnerabilities by developer").parent().contains("29").should("exist");
    cy.get("h4").contains("Vulnerabilities by developer").parent().contains("45").should("exist");
    cy.get("h4").contains("Vulnerabilities by developer").parent().contains("16").should("exist");
    cy.get("h4").contains("Vulnerabilities by developer").parent().contains("13").should("exist");
}

function CheckIfExistsVulnerabilitiesAndCanUpdateSeverityAndStatus(): void {
    // Go to vulnerabilities page
    cy.get("[data-testid=\"icon-shield\"").parent().click();
    cy.wait(1500);

    // Select first vulnerability and open Severity dropdown
    cy.get("tr>td").eq(2).children().children().click();
    cy.wait(500);

    // Change severity to HIGH
    cy.get("tr>td").eq(2).contains("HIGH").click();

    // Check if severity was updated with success
    cy.contains("Vulnerability status successfully changed!").should("exist");
    cy.wait(4000);

    // Select first vulnerability and open status dropdown
    cy.get("tr>td").eq(3).children().children().click();

    // Change status to Risk Accepted
    cy.get("tr>td").eq(3).contains("Risk Accepted").click();

    // Check if status was updated with success
    cy.contains("Vulnerability status successfully changed!").should("exist");

    // Open modal of vulnerability and check if details exists
    cy.get("tr>td").eq(4).children().children().click();
    cy.wait(500);
    cy.contains("Vulnerability Details").should("exist");
}

function CreateUserAndInviteToExistingWorkspace(): void {
    // Go to home page
    cy.visit("http://localhost:8043/");
    cy.wait(4000);
    // Logout user
    cy.get("[data-testid=\"icon-logout\"").click();
    cy.wait(3000);

    // Create new account
    cy.get("button").contains("Don't have an account? Sign up").click();
    cy.get("#username").clear().type("e2e_user");
    cy.get("#email").clear().type("e2e_user@example.com");
    cy.get("button").contains("Next").click();
    cy.get("#password").clear().type("Ch@ng3m3");
    cy.get("#confirm-pass").clear().type("Ch@ng3m3");
    cy.get("button").contains("Register").click();

    // Check if account was created
    cy.contains("Your Horusec account has been successfully created!");
    cy.get("button").contains("Ok, I got it.").click();

    // Login with new account and check if not exists company and logout user
    cy.get("#email").type("e2e_user@example.com");
    cy.get("#password").type("Ch@ng3m3");
    cy.get("button").first().click();
    cy.wait(1500);

    // Check if not exists company to this account and logout user
    cy.contains("Add a new Workspace to start using Horusec.").should("exist");
    cy.get("[data-testid=\"icon-logout\"").click();
    cy.wait(3000);

    // Login with default account
    cy.get("#email").type("dev@example.com");
    cy.get("#password").type("Devpass0*");
    cy.get("button").first().click();
    cy.wait(1500);

    // Go to manage workspace page
    cy.get("div").contains("Manage Workspaces").parent().parent().click();
    cy.get("div").contains("Manage Workspaces").click();
    cy.wait(1500);

    // Open modal to invite user
    cy.get("button").contains("Workspace users").click();
    cy.wait(500);

    // Invite user
    cy.get("button").contains("Invite User").click();
    cy.get("#email").clear().type("e2e_user@example.com");
    cy.get("h3").contains("Invite a new user below:").parent().contains("Member").parent().parent().click();
    cy.get("h3").contains("Invite a new user below:").parent().contains("Member").click();
    cy.get("button").contains("Save").click();
}

function CheckIfPermissionsIsEnableToWorkspaceMember(): void {
    // Go to home page
    cy.visit("http://localhost:8043/");
    cy.wait(4000);

    // Logout user
    cy.get("[data-testid=\"icon-logout\"").click();
    cy.wait(3000);

    // Login with new account
    cy.get("#email").type("e2e_user@example.com");
    cy.get("#password").type("Ch@ng3m3");
    cy.get("button").first().click();
    cy.wait(1500);

    // Check if not exists dashboard by workspace page
    cy.get("span").contains("Dashboard").parent().click();
    cy.wait(500);
    cy.get(":nth-child(2) > ul").contains("Dashboard").should("not.exist");

    // Go to manage workspace
    cy.get("div").contains("Manage Workspaces").parent().parent().click();
    cy.get("div").contains("Manage Workspaces").click();

    // Check if created workpspace will exists actions buttons
    cy.get("button").contains("Add Workspace").click();
    cy.wait(500);
    cy.get("#name").type("Other company");
    cy.get("button").contains("Save").click();
    cy.contains("Other company").should("exist");
    cy.get("tr").contains("Other company").parent().contains("Edit").should("exist");
    cy.get("tr").contains("Other company").parent().contains("Delete").should("exist");
    cy.get("tr").contains("Other company").parent().contains("Workspace users").should("exist");
    cy.get("tr").contains("Other company").parent().contains("Tokens").should("exist");

    // Check if is not possible see actions of workspace was invited
    cy.get("tr").contains("Company e2e").parent().contains("Edit").should("not.exist");
    cy.get("tr").contains("Company e2e").parent().contains("Delete").should("not.exist");
    cy.get("tr").contains("Company e2e").parent().contains("Workspace users").should("not.exist");
    cy.get("tr").contains("Company e2e").parent().contains("Tokens").should("not.exist");

    // Delete workspace created
    cy.get("tr").contains("Other company").parent().contains("Delete").click();
    cy.wait(500);
    cy.get("button").contains("Yes").click();
    cy.contains("Other company").should("not.exist");
}

function InviteUserToRepositoryAndCheckPermissions(repositoryName: string): void {
    // Go to home page
    cy.visit("http://localhost:8043/");
    cy.wait(4000);

    // Logout user
    cy.get("[data-testid=\"icon-logout\"").click();
    cy.wait(4000);

    // Login with default user
    cy.get("#email").type("dev@example.com");
    cy.get("#password").type("Devpass0*");
    cy.get("button").first().click();
    cy.wait(1500);

    // Go to repositories page
    cy.get("span").contains("Repositories").parent().click();
    cy.wait(1500);

    // Invite user to repository
    cy.get("tr").contains(repositoryName).parent().contains("Invite").click();
    cy.wait(500);
    cy.get("tr").contains("e2e_user").parent().children().children().children().first().click();
    cy.wait(500);
    cy.get("span").contains("Success in adding user to the repository!");

    // Logout user
    cy.visit("http://localhost:8043/");
    cy.wait(4000);
    cy.get("[data-testid=\"icon-logout\"").click();
    cy.wait(4000);

    // Login with new user
    cy.get("#email").type("e2e_user@example.com");
    cy.get("#password").type("Ch@ng3m3");
    cy.get("button").first().click();
    cy.wait(1500);

    // Check if dashboard show data to repository
    cy.contains(repositoryName).should("exist");
    cy.get("h4").contains("Total developers").parent().contains("1").should("exist");

    // Go to repositories page
    cy.get("span").contains("Repositories").parent().click();
    cy.wait(1500);
    // Check if user not contains permissions
    cy.get("tr").contains(repositoryName).parent().contains("Edit").should("not.exist");
    cy.get("tr").contains(repositoryName).parent().contains("Delete").should("not.exist");
    cy.get("tr").contains(repositoryName).parent().contains("Invite").should("not.exist");
    cy.get("tr").contains(repositoryName).parent().contains("Tokens").should("not.exist");

    // Logout user
    cy.get("[data-testid=\"icon-logout\"").click();
    cy.wait(4000);
}

function LoginAndUpdateDeleteAccount(): void {
    // Login with new account
    cy.get("#email").type("e2e_user@example.com");
    cy.get("#password").type("Ch@ng3m3");
    cy.get("button").first().click();
    cy.wait(1500);

    cy.get("[data-testid=\"icon-config\"").click();

    // Open modal and edit user
    cy.get("button").contains("Edit").click();
    cy.get("#nome").clear().type("user_updated");
    cy.get("#email").clear().type("user_updated@example.com");
    cy.get("button").contains("Save").click();

    // Check if user was edited with success
    cy.contains("user_updated").should("exist");
    cy.contains("user_updated@example.com").should("exist");

    // Logout user
    cy.get("[data-testid=\"icon-logout\"").click();
    cy.wait(4000);

    // Check if is enable login with new email
    cy.get("#email").type("user_updated@example.com");
    cy.get("#password").type("Ch@ng3m3");
    cy.get("button").first().click();
    cy.wait(1500);

    // Go to config page
    cy.get("[data-testid=\"icon-config\"").click();
    cy.wait(1500);

    // Change password of user
    cy.get("button").contains("Password").click();
    cy.get("#password").clear().type("Ch@ng3m3N0w");
    cy.get("#confirm-pass").clear().type("Ch@ng3m3N0w");
    cy.get("button").contains("Save").click();

    // Logout user
    cy.get("[data-testid=\"icon-logout\"").click();
    cy.wait(4000);

    // Check if is enable login with new password
    cy.get("#email").type("user_updated@example.com");
    cy.get("#password").type("Ch@ng3m3N0w");
    cy.get("button").first().click();
    cy.wait(1500);

    // When login in page check if exist "Version" o system
    cy.contains("Version").should("exist");

    // Go to config page
    cy.get("[data-testid=\"icon-config\"").click();
    cy.wait(1500);

    // Delete account
    cy.get("button").contains("Delete").click();
    cy.get("button").contains("Yes").click();
    cy.wait(5000);

    // Check if account not exists
    cy.get("#email").type("user_updated@example.com");
    cy.get("#password").type("Ch@ng3m3N0w");
    cy.get("button").first().click();

    // Check if login is not authorized
    cy.get("span").contains("Check your e-mail and password and try again.");
    cy.contains("Version").should("not.exist");
}

