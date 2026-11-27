export class AuthError extends Error { constructor(readonly code:string,readonly status=0){super(code);} }
export const object=(v:unknown):v is Record<string,unknown>=>!!v&&typeof v==='object'&&!Array.isArray(v);
export interface AuthRequest { method?:'GET'|'POST'|'PUT';body?:unknown;csrf?:string;revision?:string;expectedStatus?:202;emptyStatus?:202; }
// Fixed paths are provided by domain adapters. Cookies never leave this origin.
export async function authJSON(path:string,options:AuthRequest={}):Promise<unknown>{
  const controller=new AbortController(),timer=setTimeout(()=>controller.abort(),15000);
  try{
    const method=options.method??'GET',headers:Record<string,string>={Accept:'application/json'};
    if(method!=='GET'){headers['Content-Type']='application/json';headers['X-CSRF-Token']=options.csrf??'';if(options.revision!==undefined)headers['If-Match']='"'+options.revision+'"';}
    const response=await fetch(path,{method,credentials:'same-origin',cache:'no-store',redirect:'error',headers,signal:controller.signal,...(method==='GET'?{}:{body:JSON.stringify(options.body)})});
    if(response.ok&&options.expectedStatus!==undefined&&response.status!==options.expectedStatus)throw new AuthError('invalid_response',response.status);
    if(!response.body&&response.status===options.emptyStatus)return undefined;
    if(!response.body||Number(response.headers.get('content-length'))>65536)throw new AuthError('invalid_response',response.status);
    const reader=response.body.getReader(),chunks:Uint8Array[]=[];let size=0;
    try{for(;;){const chunk=await reader.read();if(chunk.done)break;size+=chunk.value.length;if(size>65536){await reader.cancel();throw new AuthError('invalid_response',response.status);}chunks.push(chunk.value);}}finally{reader.releaseLock();}
    if(response.status===options.emptyStatus){if(size!==0)throw new AuthError('invalid_response',response.status);return undefined;}
    const bytes=new Uint8Array(size);let at=0;for(const chunk of chunks){bytes.set(chunk,at);at+=chunk.length;}let data:unknown;
    try{data=JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(bytes));}catch{throw new AuthError('invalid_response',response.status);}
    if(!response.ok)throw new AuthError(object(data)&&typeof data['code']==='string'?data['code']:object(data)&&typeof data['error']==='string'?data['error']:'request_failed',response.status);
    return data;
  }catch(e:unknown){if(e instanceof AuthError)throw e;throw new AuthError(controller.signal.aborted?'request_timeout':'network_error');}finally{clearTimeout(timer);controller.abort();}
}
export function csrfCookie(name:string):string{const matches=document.cookie.split(';').map(v=>v.trim()).filter(v=>v.startsWith(name+'='));if(matches.length!==1)throw new AuthError('csrf_required',403);let token='';try{token=decodeURIComponent(matches[0].slice(name.length+1));}catch{throw new AuthError('csrf_required',403);}if(!/^[A-Za-z0-9_-]{32,256}$/.test(token))throw new AuthError('csrf_required',403);return token;}
