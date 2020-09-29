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

const OrganizationInviteTpl = `<!DOCTYPE
  html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html xmlns="http://www.w3.org/1999/xhtml">
 <head>
  <meta http-equiv="Content-Type" content="text/html; charset=UTF-8" />
  <title>Demystifying Email Design</title>
  <meta name="viewport" content="width=device-width, initial-scale=1.0"/>
  <style>
    html {
      font-family: arial;
    }

    .header, .footer {
      padding: 40px;
    }

    .action, .content {
      padding: 20px;
      font-size: 22px;
    }

    .button {
      display: inline-block;
      margin: 10px 0;
      min-width: 100px;
      border-radius: 3px;
      background-color: #8dc63f;
      color: #fafafa;
      padding: 5px 10px;
      text-decoration: none;
      font-size: 32px;
    }
  </style>
</head>
<body style="margin: 0; padding: 20px 0 0 0;">

<table align="center" border="0" cellpadding="0" cellspacing="0" width="600" bgcolor="#e1e6f5" margin-top="20px">
 <tr>
  <td align="center" class="header">
   <img
    src="https://horus-assets.s3.amazonaws.com/images/horus_logo_200921.svg"
    width="80" />
  </td>
 </tr>
 <tr>
  <td class="content">
	Olá <b>{{.Username}}</b>, você foi convidado para participar da organização <b>{{.CompanyName}}.</b>
	<br>
  </td>
 </tr>
 <tr>
  <td class="action" align="center">
	<a class="button" href="{{.URL}}">Aceitar convite</a>
   </td>
 </tr>
 <tr>
  <td align="center" class="footer">
   <img width="60" src="https://avatars1.githubusercontent.com/u/967526?s=200&v=4" />
  </td>
 </tr>
</table>

</body>
</html>`
