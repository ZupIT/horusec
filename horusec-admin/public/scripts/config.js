function setCurrentValues() {
    const xhr = new XMLHttpRequest();
    xhr.open('GET', '/api/config', true);
    xhr.setRequestHeader("Content-Type", "application/json;charset=UTF-8");
    xhr.setRequestHeader('authorization', getCookie('horusec::access_token'))

    xhr.send()

    xhr.onreadystatechange = function (ev) {
        if (ev.currentTarget.status === 200 && ev.currentTarget.response) {
            const result = JSON.parse(ev.currentTarget.response)

             Object.entries(result).forEach(item => {
                const element = document.getElementById(item[0])

                if (element) {
                    element.value = item[1]

                    if (element.type === 'checkbox' && item[1]) {
                        element.checked = JSON.parse(item[1])
                    }

                    if (item[0] === 'horusec_auth_type') {
                        setAuthType(item[1], true)
                    }
                }
            });
        }
    }
}
function setAuthType(authType, setRadioOption) {
    document.getElementById('horusec_auth_type').value = authType

     document.getElementById('keycloak-form').style.display = 'none'
     document.getElementById('ldap-form').style.display = 'none'

    if (authType !== 'horusec') {
         document.getElementById(`${authType}-form`).style.display = 'flex'
    }

    if (setRadioOption) {
        document.getElementById(`auth-${authType}`).checked = true
    }
 }