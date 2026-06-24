document.addEventListener("DOMContentLoaded",()=>{const configs=[
  ["device-chart","device-chart-data","doughnut"],["severity-chart","severity-chart-data","bar"],
  ["daily-chart","daily-chart-data","line"],["risk-chart","risk-chart-data","line"],
  ["device-report-chart","device-report-chart-data","doughnut"],["service-chart","service-chart-data","bar"]
];if(typeof Chart==="undefined")return;configs.forEach(([canvasId,dataId,type])=>{const canvas=document.getElementById(canvasId),node=document.getElementById(dataId);if(!canvas||!node)return;const data=JSON.parse(node.textContent);new Chart(canvas,{type,data:{labels:data.labels,datasets:[{label:"Kayıt",data:data.values,backgroundColor:["#38bdf8","#f59e0b","#ef4444","#8b5cf6"],borderColor:"#38bdf8",borderWidth:2,tension:.3}]},options:{responsive:true,maintainAspectRatio:false,plugins:{legend:{labels:{color:"#cbd5e1"}}},scales:type==="doughnut"?{}:{x:{ticks:{color:"#93a4ba"}},y:{beginAtZero:true,ticks:{color:"#93a4ba"}}}}});});});
