<#
.SYNOPSIS
    Get current user's Dropbox DBX decryption keys.
.DESCRIPTION
    The script accesses the Current User Registry keys 'ks' and 'ks1', both
    containing the Dropbox User keys protected by DPAPI. It decryptes the blobs
    and it derives the Dropbox DBX decryption keys.
.OUTPUTS
    User's Drobox keys and DBX decryption keys.
.NOTES
    Copyright 2017, Francesco "dfirfpi" Picasso <francesco.picasso@gmail.com>

    Licensed under the Apache License, Version 2.0 (the "License");
    you may not use this file except in compliance with the License.
    You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

    Unless required by applicable law or agreed to in writing, software
    distributed under the License is distributed on an "AS IS" BASIS,
    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
    See the License for the specific language governing permissions and
    limitations under the License.
.EXAMPLE
    .\dbx-keygen-windows.ps1
.LINK
    https://github.com/dfirfpi/decwindbx
    https://github.com/newsoft/dbx-keygen-windows
#>
Add-Type -AssemblyName System.Security

$ErrorActionPreference = 'Stop'


function dbx_keygen_v0($ks_name)
{
    [Byte[]] $dv0_entropy = 0xd1,0x14,0xa5,0x52,0x12,0x65,0x5f,0x74,0xbd,0x77,
                            0x2e,0x37,0xe6,0x4a,0xee,0x9b

    $key_path = "HKCU:\SOFTWARE\Dropbox\$ks_name"
    Write-Output "Working with key $key_path"

    try {
        $key_bin = (Get-ItemProperty -Path $key_path -Name Client).Client

        $key_version = [BitConverter]::ToUInt32($key_bin, 0)
        if ($key_version -ne 0) {
            Write-Warning "Got version $key_version, expected 0."
            Write-Warning "High likely the resulting DBX key will be wrong!"
        }

        $blob_len = [BitConverter]::ToUInt32($key_bin, 4)
        # Note the -2, to get rid of last null byte.
        $key_hmac = $key_bin[(8+$blob_len)..($key_bin.length-2)]
        $blob_enc = $key_bin[8..(8+$blob_len-1)]
    }
    catch {
        Write-Error 'The Dropbox key does not exist or its type is unknown.'
    }
    Write-Output "Registry key accessed, got version $key_version"

    $OBJ_hmac = New-Object System.Security.Cryptography.HMACMD5
    $OBJ_hmac.key = $dv0_entropy
    $verify_hmac = $OBJ_hmac.ComputeHash($key_bin[0..(8+$blob_len-1)])

    if (Compare-Object $key_hmac $verify_hmac) {
        Write-Warning "Registry Key HMAC does not match!"
        [System.BitConverter]::ToString($key_hmac)
        [System.BitConverter]::ToString($verify_hmac)
        Write-Warning "Tesulting DBX key could be wrong!"
    }

    try {
        $blob_dec = [System.Security.Cryptography.ProtectedData]::Unprotect(
        $blob_enc, $dv0_entropy,
        [System.Security.Cryptography.DataProtectionScope]::CurrentUser)
    }
    catch {
        Write-Error 'Unable to decrypt the key DPAPI BLOB.'
    }
    $tmp = [System.BitConverter]::ToString($blob_dec).Replace(
        '-', [System.String]::Empty)
    Write-Output "User key [$ks_name]: $tmp"

    [Byte[]] $salt = 0x0D,0x63,0x8C,0x09,0x2E,0x8B,0x82,0xFC,0x45,0x28,0x83,
                     0xF9,0x5F,0x35,0x5B,0x8E

    $OBJ_pbkdf2 = New-Object System.Security.Cryptography.Rfc2898DeriveBytes(
        $blob_dec, $salt, 1066)

    $dbx_key = $OBJ_pbkdf2.GetBytes(16)
    $tmp = [System.BitConverter]::ToString($dbx_key).Replace(
        '-', [System.String]::Empty)
    Write-Output "DBX  key [$ks_name]: $tmp"
}

Write-Output ' '
dbx_keygen_v0('ks')
Write-Output ' '
dbx_keygen_v0('ks1')
