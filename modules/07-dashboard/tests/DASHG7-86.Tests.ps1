Describe "DASHG7-86 - Pruebas de cierre de sesión y caducidad" {

    $authPath = Join-Path $PSScriptRoot "..\src\auth-client.js"
    $indexPath = Join-Path $PSScriptRoot "..\src\index.html"

    $auth = Get-Content $authPath -Raw
    $index = Get-Content $indexPath -Raw

    Context "Cierre de sesión" {

        It "Elimina el token de sessionStorage" {
            $auth | Should Match 'sessionStorage\.removeItem\(TOKEN_KEY\)'
        }

        It "Elimina el indicador logged_in" {
            $auth | Should Match 'sessionStorage\.removeItem\("logged_in"\)'
        }

        It "Llama al endpoint de logout de Identidad" {
            $auth | Should Match '/auth/logout'
        }

        It "Envía el token en la cabecera Authorization" {
            $auth | Should Match 'Authorization:\s*`Bearer \$\{token\}`'
        }

        It "El botón de cierre de sesión está presente" {
            $index | Should Match 'Cerrar Sesión'
        }
    }

    Context "Validación y caducidad del token" {

        It "Consulta el endpoint auth/validate" {
            $auth | Should Match '/auth/validate'
        }

        It "Envía el token para validarlo" {
            $auth | Should Match 'Authorization:\s*`Bearer \$\{token\}`'
        }

        It "Elimina el token cuando Identidad responde 401" {
            $auth | Should Match 'result\.status\s*===\s*401'
        }

        It "Redirige al login cuando la sesión no es válida" {
            $auth | Should Match 'window\.location\.replace\("login\.html"\)'
        }

        It "Permite continuar cuando el token es válido" {
            $auth | Should Match 'if\s*\(result\.valid\)'
        }
    }

    Context "Integración del botón de cierre de sesión" {

        It "El botón invoca la función logout" {
            $index | Should Match 'onclick="logout\(\)"'
        }

        It "La función del botón redirige al login" {
            $index | Should Match 'window\.location\.href\s*=\s*"login\.html"'
        }
    }
}