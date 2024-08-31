const DEVELOPMENT_CONFIG = {
  encryptedScript: false,
  scriptUrl: 'http://localhost:62273/main.js',
};

const PRODUCTION_CONFIG = {
  encryptedScript: true,
  passwordLocationInLocalStorage: 'kanmitsu_password',
  sha256password: 'a30a0c22bf435c9d9bf1cd0a310df626810cf6159405009fcce9f1920dd44c9b',
  scriptUrl: 'https://gist.githubusercontent.com/KcB6hzra/edd0df80bcaa64e3f8325e2f706a89dc/raw/test3.js',
};

const config = location.hostname === 'localhost' ? DEVELOPMENT_CONFIG : PRODUCTION_CONFIG;

loadScript();

async function loadScript() {
  const script = await resolveScript();
  const scriptElement = document.createElement('script');
  scriptElement.type = 'module';
  scriptElement.innerHTML = script;
  document.head.appendChild(scriptElement);
}

async function resolveScript() {
  if (!config.encryptedScript) {
    return await (await fetch(config.scriptUrl)).text();
  } else {
    const password = localStorage.getItem(config.passwordLocationInLocalStorage);
    if (await sha256(password) === config.sha256password) {
      const encryptedBase64 = await (await fetch(config.scriptUrl)).text();
      const passwordBytes = new TextEncoder().encode(password);
      const passwordKey = await importKey(passwordBytes);
      const encryptedBytes = base64decode(encryptedBase64);
      const bytes = await decrypt(encryptedBytes, passwordKey);
      return new TextDecoder().decode(bytes);
    } else {
      throw 'wrong password';
    }
  }
}

async function sha256(text) {
  const bytes  = new TextEncoder().encode(text);
  const digest = await crypto.subtle.digest('SHA-256', bytes);
  return Array.from(new Uint8Array(digest)).map(v => v.toString(16).padStart(2, '0')).join('');
}

async function importKey(passwordBytes) {
  return await crypto.subtle.importKey('raw', passwordBytes, 'PBKDF2', false, ['deriveKey']);
}

function base64decode(base64) {
  const binaryString = atob(base64);
  return Uint8Array.from(binaryString, s => s.codePointAt(0));
}

async function deriveSharedKey(passwordKey, salt) {
  return await crypto.subtle.deriveKey({
    name: 'PBKDF2',
    salt: salt,
    iterations: 2000,
    hash: 'SHA-256',
  }, passwordKey, {
      name: 'AES-GCM',
      length: 256,
  }, true, ['encrypt', 'decrypt']);
}

async function decrypt(encryptedBytes, passwordKey) {
  const salt = encryptedBytes.subarray(0, 16);
  const iv = encryptedBytes.subarray(16, 32);
  const encryptedContent = encryptedBytes.subarray(32);
  const sharedKey = await deriveSharedKey(passwordKey, salt);

  return new Uint8Array(await crypto.subtle.decrypt({
    name: 'AES-GCM',
    iv,
    tagLength: 128,
  }, sharedKey, encryptedContent));
}
