// Copyright 2020 ZUP IT SERVICOS EM TECNOLOGIA E INOVACAO SA
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//nolint
package templates

const EmailConfirmationTpl = `<!doctype html>
<html>
<head>
  <meta name="viewport" content="width=device-width" />
  <meta http-equiv="Content-Type" content="text/html; charset=UTF-8" />
  <link href="https://fonts.googleapis.com/css2?family=Roboto&display=swap" rel="stylesheet">
  <title>HORUSEC - Verificação de e-mail</title>
  <style>
    img {
      border: none;
      -ms-interpolation-mode: bicubic;
      max-width: 100%;
    }
    .logo-wrapper,
    div.footer {
      margin-top: 80px;
      margin-bottom: 80px;
    }
    p.team {
      color: #07002C;
      font-size: 12px;
      letter-spacing: -0.08px;
    }
    span.copyright,
    span.powered {
      color: #07002C;
      font-size: 12px;
      letter-spacing: 0;
      line-height: NaNpx;
      font-family: 'Roboto', sans-serif;
    }
    span.powered {
      margin-left: 50px;
    }
    body {
      background-color: #f6f6f6;
      font-family: 'Roboto', sans-serif;
      -webkit-font-smoothing: antialiased;
      font-size: 14px;
      line-height: 1.4;
      margin: 0;
      padding: 0;
      -ms-text-size-adjust: 100%;
      -webkit-text-size-adjust: 100%;
    }
    table {
      border-collapse: separate;
      mso-table-lspace: 0pt;
      mso-table-rspace: 0pt;
      width: 100%;
    }
    table td {
      font-family: 'Roboto', sans-serif;
      font-size: 14px;
      vertical-align: top;
    }
    .body {
      background-color: #f6f6f6;
      width: 100%;
    }
    .container {
      display: block;
      margin: 0 auto !important;
      max-width: 600px;
      padding: 10px;
      width: 600px;
    }
    .content {
      box-sizing: border-box;
      display: block;
      margin: 0 auto;
      max-width: 600px;
      padding: 10px;
    }
    .main {
      background: #ffffff;
      border-radius: 3px;
      width: 100%;
    }
    .wrapper {
      box-sizing: border-box;
      padding: 50px;
    }
    h1 {
      font-size: 20px;
      font-weight: 300;
      text-align: center;
      text-transform: capitalize;
      color: #07002C;
      font-family: 'Roboto', sans-serif;
      font-weight: 400;
      line-height: 1.4;
      margin: 0;
      margin-bottom: 15px;
    }
    p {
      font-family: 'Roboto', sans-serif;
      font-size: 16px;
      font-weight: normal;
      margin: 0;
      margin-bottom: 15px;
      color: #07002C;
      list-style-position: inside;
    }
    .btn {
      box-sizing: border-box;
      width: 100%;
      margin-top: 40px;
    }
    .btn>tbody>tr>td {
      padding-bottom: 15px;
    }
    .btn table {
      width: auto;
    }
    .btn table td {
      background-color: #ffffff;
      border-radius: 5px;
      text-align: center;
    }
    .btn a {
      background-color: #ffffff;
      border-radius: 5px;
      box-sizing: border-box;
      cursor: pointer;
      display: inline-block;
      font-size: 12px;
      font-weight: normal;
      margin: 0;
      padding: 12px 25px;
      text-decoration: none;
      border-radius: 25px;
    }
    .btn-primary table td {
      border-radius: 25px;
    }
    .btn-primary a {
      background: linear-gradient(90deg, #EF4123 0%, #F7941E 100%);
      color: #ffffff;
    }
    .align-center {
      text-align: center;
    }
    .align-right {
      text-align: right;
    }
    .align-left {
      text-align: left;
    }
    .preheader {
      color: transparent;
      display: none;
      height: 0;
      max-height: 0;
      max-width: 0;
      opacity: 0;
      overflow: hidden;
      mso-hide: all;
      visibility: hidden;
      width: 0;
    }

    @media only screen and (max-width: 620px) {
      span.copyright,
      span.powered {
        display: inline;
        margin: 0;
        display: inline-block;
      }
      table[class=body] h1 {
        font-size: 28px !important;
        margin-bottom: 10px !important;
      }
      table[class=body] p,
      table[class=body] ul,
      table[class=body] ol,
      table[class=body] td,
      table[class=body] span,
      table[class=body] a {
        font-size: 16px !important;
      }
      table[class=body] .wrapper,
      table[class=body] .article {
        padding: 10px !important;
      }
      table[class=body] .content {
        padding: 0 !important;
      }
      table[class=body] .container {
        padding: 0 !important;
        width: 100% !important;
      }
      table[class=body] .main {
        border-left-width: 0 !important;
        border-radius: 0 !important;
        border-right-width: 0 !important;
      }
      table[class=body] .btn table {
        width: 100% !important;
      }
      table[class=body] .btn a {
        width: 100% !important;
      }
      table[class=body] .img-responsive {
        height: auto !important;
        max-width: 100% !important;
        width: auto !important;
      }
    }

    @media all {
      .ExternalClass {
        width: 100%;
      }
      .ExternalClass,
      .ExternalClass p,
      .ExternalClass span,
      .ExternalClass font,
      .ExternalClass td,
      .ExternalClass div {
        line-height: 100%;
      }
      #MessageViewBody a {
        color: inherit;
        text-decoration: none;
        font-size: inherit;
        font-family: inherit;
        font-weight: inherit;
        line-height: inherit;
      }
    }
  </style>
</head>
<body class="">
  <span class="preheader">HORUSEC - Email verification</span>
  <table role="presentation" border="0" cellpadding="0" cellspacing="0" class="body">
    <tr>
      <td>&nbsp;</td>
      <td class="container">
        <div class="content">
          <table role="presentation" class="main">
            <tr>
              <td class="wrapper">
                <table role="presentation" border="0" cellpadding="0" cellspacing="0">
                  <tr>
                    <td>
                      <p class="align-center logo-wrapper">
                        <img width="150px" src="https://horusec.io/public/email_logo.png">
                      </p>
                      <h1 class="align-left">Hello, {{.Username}}!</h1>
                      <p>To start using Horusec, confirm your email.</p>
                      <table role="presentation" border="0" cellpadding="0" cellspacing="0" class="btn btn-primary">
                        <tbody>
                          <tr>
                            <td align="left">
                              <table role="presentation" border="0" cellpadding="0" cellspacing="0">
                                <tbody>
                                  <tr>
                                    <td> <a href="{{.URL}}" target="_blank">Check email</a>
                                    </td>
                                  </tr>
                                </tbody>
                              </table>
                            </td>
                          </tr>
                        </tbody>
                      </table>
                      <div class="footer">
                        <p class="team">Horusec Team</p>
                        <span class="copyright">© 2020 Horusec Sec. All rights reserved.</span>
                        <span class="powered">Powered by Zup I. T. Innovation</span>
                      </div>
                    </td>
                  </tr>
                </table>
              </td>
            </tr>
          </table>
        </div>
      </td>
      <td>&nbsp;</td>
    </tr>
  </table>
</body>
</html>
`
