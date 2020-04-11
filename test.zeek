global temp :table[addr] of set[string]= table();

event http_header(c: connection, is_orig: bool, name :string, value :string){
  local ad :addr=c$id$orig_h;
  local low :string=to_lower(value);
  if(name=="USER-AGENT"){
    if(ad in temp){
      add temp[ad][low];
    }
    else{
      temp[ad]=set(low);
    }
  }
}

event zeek_done(){
  local s :string=" is a proxy";
  for(i in temp){
    if((|temp[i]|)>=3)
      print i,s;
  }
}
