$(document).ready(function(){
    //connect to the socket server.
    var socket = io.connect('http://' + document.domain + ':' + location.port + '/test');
    var messages_received = [];
    var ctx = document.getElementById("myChart");
    var myChart = new Chart(ctx, {
        type: 'bar',
        data: {
            labels: [],
            datasets: [{
                data: [],
                backgroundColor: [
                    // 'rgba(255, 99, 132, 0.2)',
                    // 'rgba(54, 162, 235, 0.2)',
                    // 'rgba(255, 206, 86, 0.2)',
                    // 'rgba(75, 192, 192, 0.2)',
                    // 'rgba(153, 102, 255, 0.2)'
                ],
                borderColor: [
                    // 'rgba(255,99,132,1)',
                    // 'rgba(54, 162, 235, 1)',
                    // 'rgba(255, 206, 86, 1)',
                    // 'rgba(75, 192, 192, 1)',
                    // 'rgba(153, 102, 255, 1)'
                ],
                borderWidth: 1
            }]
        },
        options: {

                legend: {
                  display: false
                }
              ,
            scales: {
    
                yAxes: [{
                    ticks: {
                        beginAtZero:true
                    }
                }]
            }
        }
    });

    //receive details from server
    socket.on('newresult', function(msg) {
        console.log("Received result" + msg.result);
        //maintain a list of ten messages
        if (messages_received.length >= 10){
            messages_received.shift()
        }            
        messages_received.push(msg.result);
        var tbody = '';
        for (var i = messages_received.length-1 ; i >= 0; i--){
            tbody += '<tr>';
            tbody += '<td>' + messages_received[i][0] + '</td>'; // Flow ID
            tbody += '<td>' + messages_received[i][1] + '</td>'; // Src IP
            tbody += '<td>' + messages_received[i][2] + '</td>'; // Src Port
            tbody += '<td>' + messages_received[i][3] + '</td>'; // Dst IP
            tbody += '<td>' + messages_received[i][4] + '</td>'; // Dst Port
            tbody += '<td>' + messages_received[i][5] + '</td>'; // Protocol
            tbody += '<td>' + messages_received[i][10] + '</td>'; // Prediction
            tbody += '<td>' + messages_received[i][12] + '</td>'; // Risk
            tbody += '<td><a href="/flow-detail?flow_id=' + messages_received[i][0] + '" class="btn btn-xs btn-info"><i class="fa fa-eye"></i> View</a></td>'; // Details
            tbody += '</tr>';
        }
        $('#details tbody').html(tbody);

        // var i = 0;
        // Object.keys(msg.ips).forEach(function(key) {
        //     myChart.data.datasets[0].data[i] = msg.ips[key] ;
        //     myChart.data.labels[i] =key;
        //     i = i+1;
        //   })

        for (var i=0; i < msg.ips.length; i++) {
            myChart.data.datasets[0].data[i] =msg.ips[i].count;
            myChart.data.labels[i] =msg.ips[i].SourceIP;
           
           }
           
               myChart.update();

        myChart.update();


    });

});



