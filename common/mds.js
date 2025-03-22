// https://github.com/passkeydeveloper/passkeyauthenticatoraaguids/blob/main/aaguid.json
providers = {
	'ea9b8d664d011d213ce4b6b48cb575d4': 'Google Password Manager',
	'adce000235bcc60a648b0b25f1f05503': 'Chrome on Mac',
	'08987058cadc4b81b6e130de50dcbe96': 'Windows Hello',
	'9ddd1817af5a4672a2b93e3dd95000a9': 'Windows Hello',
	'6028b017b1d44c02b4b3afcdafc96bb2': 'Windows Hello',
	'dd4ec289e01d41c9bb8970fa845d4bf2': 'iCloud Keychain (Managed)',
	'531126d6e717415c93203d9aa6981239': 'Dashlane',
	'bada5566a7aa401fbd9645619a55120d': '1Password',
	'b84e404815dc4dd08640f4f60813c8af': 'NordPass',
	'0ea242b443c44a1b8b17dd6d0b6baec6': 'Keeper',
	'891494da2c904d31a9cd4eab0aed1309': 'Sésame',
	'f38095407f1449c1a8b38f813b225541': 'Enpass',
	'b53976664885aa6bcebfe52262a439a2': 'Chromium Browser',
	'771b48fdd3d44f749232fc157ab0507a': 'Edge on Mac',
	'39a5647e1853446ca1f6a79bae9f5bc7': 'IDmelon',
	'd548826e79b4db40a3d811116f7e8349': 'Bitwarden',
	'fbfc3007154e4ecc8c0b6e020557d7bd': 'iCloud Keychain',
	'53414d53554e47000000000000000000': 'Samsung Pass',
	'66a0ccb3bd6a191fee06e375c50b9846': 'Thales Bio iOS SDK',
	'8836336af5900921301d46427531eee6': 'Thales Bio Android SDK',
	'cd69adb53c7adeb931776800ea6cb72a': 'Thales PIN Android SDK',
	'17290f1ec21234d01423365d729f09d9': 'Thales PIN iOS SDK',
	'50726f746f6e5061737350726f746f6e': 'Proton Pass',
	'fdb141b25d84443e8a354698c205a502': 'KeePassXC',
	'cc45f64e52a2451b831a4edd8022a202': 'ToothPic Passkey Provider',
};

function base64URLdecode(str) {
  const base64Encoded = str.replace(/-/g, '+').replace(/_/g, '/');
  const padding = str.length % 4 === 0 ? '' : '='.repeat(4 - (str.length % 4));
  const base64WithPadding = base64Encoded + padding;
  return atob(base64WithPadding)
    .split('')
    .map(char => String.fromCharCode(char.charCodeAt(0)))
    .join('');;
}

let json = null;

async function mds(aaguid) {
  if( !json ) {
console.log(json)
  console.log(`lookup AAGUID ${aaguid} in MDS`);
  const response = await fetch("https://mds.fidoalliance.org/", { mode: "cors" } );
  const jwt = await response.text();
  const parts = jwt.split('.');
  console.assert(parts.length == 3);
  const body = parts[1];
  const decoded = base64URLdecode(body);
  json = JSON.parse(decoded);
  console.log(`loaded ${json.entries.length} entries`);
  }
  for( i in json.entries ) {
    entry = json.entries[i];
    if(entry.aaguid == aaguid) {
      console.log(entry)
      return entry;
    }
  }
  return null;
}

function Uuid(s) {
  return 'xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx'.split('').reduce(
    (e,x) => e + (x=='-' ? '-' : s[e.replace(/-/g,'').length]),
    ''
  )
}

// MDS entry to yaml
function pp(obj, level=0, skipindent=false) {
  const indent = "  ".repeat(level);
  switch (typeof(obj)) {
    case 'boolean':
    case 'number':
    case 'string':
      return `${ skipindent ? '' : indent }${obj}`;
      break;
    case 'object':
      let result = '';
      const keys = Object.keys(obj);
      for(n in keys) {
        const key = keys[n];
        const value = obj[key];
        result += skipindent && n==0 ? '' : indent;
        result += Array.isArray(obj) ? "-" : `${key}:`;
        if( typeof(value) == 'object' )
          if( Array.isArray(obj) )
            result += " " + pp(value, level+1, true);
          else
            result += "\n" + pp(value, level+1);
        else
          result += " " + value;
        if( result.slice(-1) != '\n' ) result += '\n';
      }
      return result;
      break;
    default:
      console.error(`ERROR ${typeof(obj)}`);
  }
}
