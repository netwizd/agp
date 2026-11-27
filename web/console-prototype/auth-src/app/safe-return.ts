export function safeReturnPath(value:string|null):string {
  if(!value||value.length>2048||!value.startsWith('/')||value.startsWith('//')||/[\\\u0000-\u001f\u007f]/.test(value))return '';
  try{const url=new URL(value,location.origin);if(url.origin!==location.origin||url.pathname==='/auth-ui'||url.pathname.startsWith('/auth-ui/')&&url.pathname!=='/auth-ui/contacts')return '';return url.pathname+url.search+url.hash;}catch{return '';}
}
