"use strict";(self["webpackChunkfornt_end_vue"]=self["webpackChunkfornt_end_vue"]||[]).push([[47],{5020:function(o,l,n){n.r(l),n.d(l,{default:function(){return k}});var e=n(3396),c=n(7139),s=n(9242),t=n(4870);const u={class:"card"},a=(0,e._)("div",{class:"card-header"},"Exam01EventHandling",-1),r={class:"card-body"},d=(0,e._)("h6",null,"[Event Hanling]",-1),i=(0,e._)("h6",null,"[DOM Event 객체 참조]",-1),m=["value"],p=(0,e._)("br",null,null,-1),v=(0,e._)("h6",null,"[이벤트 수식어 사용]",-1),g=["onClick"],_=["onSubmit"],b=(0,e.Uk)(),f=(0,e._)("br",null,null,-1),h=(0,e._)("input",{type:"submit",value:"제출",class:"btn btn-success btn-sm mt-2"},null,-1);var y={setup(o){const l=(0,t.iH)("");function n(){console.log("handleBtn1() 실행")}function y(o,l){console.log("handleBtn2() 실행"),console.log("message :"+o),console.log(l),console.log(l.target)}function w(o){console.log("handleInput(event) 실행"),console.log(o.target),console.log(o.target.name),console.log(o.target.value),l.value=o.target.value}function k(){console.log("handleLink")}function P(){console.log("handleForm")}return(o,t)=>((0,e.wg)(),(0,e.iD)("div",u,[a,(0,e._)("div",r,[(0,e._)("div",null,[d,(0,e._)("button",{onClick:n,class:"btn btn-info btn-sm mr-2"},"버튼1"),(0,e._)("button",{onClick:t[0]||(t[0]=o=>y("vue is good",o)),class:"btn btn-info btn-sm mr-2"},"버튼2")]),(0,e._)("div",null,[i,(0,e._)("input",{type:"text",name:"userId",value:l.value,onKeyup:t[1]||(t[1]=o=>w(o))},null,40,m),p,(0,e.Uk)(" 입력 내용: "+(0,c.zw)(l.value),1)]),(0,e._)("div",null,[v,(0,e._)("a",{href:"https://vuejs.org/guide/introduction.html",onClick:(0,s.iM)(k,["prevent"])},"링크",8,g),(0,e._)("form",{action:"https://vuejs.org/guide/introduction.html",onSubmit:(0,s.iM)(P,["prevent"])},[(0,e.wy)((0,e._)("input",{type:"text","onUpdate:modelValue":t[2]||(t[2]=o=>l.value=o)},null,512),[[s.nr,l.value]]),b,f,h],40,_)])])]))}};const w=y;var k=w},5259:function(o,l,n){n.r(l),n.d(l,{default:function(){return U}});var e=n(3396),c=n(9242),s=n(4870);const t={class:"card"},u=(0,e._)("div",{class:"card-header"},"Exam02Watch",-1),a={class:"card-body"},r={class:"form-group row"},d=(0,e._)("label",{class:"col-sm-2 col-form-label"},"UserId",-1),i={class:"col-sm-10"},m=(0,e._)("hr",null,null,-1),p={class:"form-group row"},v=(0,e._)("label",{class:"col-sm-2 col-form-label"},"Name",-1),g={class:"col-sm-10"},_={class:"form-group row"},b=(0,e._)("label",{class:"col-sm-2 col-form-label"},"Company",-1),f={class:"col-sm-10"},h={class:"form-group row"},y=(0,e._)("label",{class:"col-sm-2 col-form-label"},"Price",-1),w={class:"col-sm-10"},k=(0,e._)("hr",null,null,-1);var P={setup(o){const l=(0,s.iH)(""),n=(0,s.iH)({name:"",company:"",price:0});function P(){n.value={name:"",company:"",price:0}}return(0,e.YP)(l,((o,l)=>{console.group("userID 변경 감시"),console.log("newUserId:",o),console.log("oldUserId:",l),console.groupEnd()})),(0,e.YP)(n,((o,l)=>{console.group("product 변경 감시"),console.log("newProduct:",o),console.log("oldProduct:",l),console.groupEnd()})),(0,e.YP)(n,((o,l)=>{console.group("product 변경 감시"),console.log("newProduct:",o),console.log("oldProduct:",l),console.groupEnd()}),{deep:!0}),(0,e.YP)((()=>n.value.name),((o,l)=>{console.group("product 객체의 name 속성 변경 감시"),console.log("newProduct:",o),console.log("oldProduct:",l),console.groupEnd()})),(0,e.YP)([l,n],(([o,l],[n,e])=>{console.group("멀티 반응형 속성 변경 감시"),console.log("new:",[o,l]),console.log("old:",[n,e]),console.groupEnd()}),{deep:!0}),(o,s)=>((0,e.wg)(),(0,e.iD)("div",t,[u,(0,e._)("div",a,[(0,e._)("div",r,[d,(0,e._)("div",i,[(0,e.wy)((0,e._)("input",{type:"text",class:"form-control","onUpdate:modelValue":s[0]||(s[0]=o=>l.value=o)},null,512),[[c.nr,l.value]])])]),m,(0,e._)("form",null,[(0,e._)("div",p,[v,(0,e._)("div",g,[(0,e.wy)((0,e._)("input",{type:"text",class:"form-control","onUpdate:modelValue":s[1]||(s[1]=o=>n.value.name=o)},null,512),[[c.nr,n.value.name]])])]),(0,e._)("div",_,[b,(0,e._)("div",f,[(0,e.wy)((0,e._)("input",{type:"text",class:"form-control","onUpdate:modelValue":s[2]||(s[2]=o=>n.value.company=o)},null,512),[[c.nr,n.value.company]])])]),(0,e._)("div",h,[y,(0,e._)("div",w,[(0,e.wy)((0,e._)("input",{type:"number",class:"form-control","onUpdate:modelValue":s[3]||(s[3]=o=>n.value.price=o)},null,512),[[c.nr,n.value.price,void 0,{number:!0}]])])])]),k,(0,e._)("button",{onClick:P,class:"btn btn-info btn-sm"},"product 객체 변경")])]))}};const E=P;var U=E}}]);
//# sourceMappingURL=menu03.d68b7eec.js.map