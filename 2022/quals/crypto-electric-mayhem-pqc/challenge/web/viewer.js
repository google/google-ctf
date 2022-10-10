// Copyright 2022 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

var selected_traces = {};
var trace_dygraph;

var PlotTraceData = function () {
  var max_samples = 0;
  for (t in selected_traces) {
    max_samples = Math.max(max_samples, selected_traces[t].length);
  }

  // convert traces data to a multidim array:
  // data = [
  //   [1, trace1_sample1, trace2_sample1],
  //   [2, trace1_sample2, trace2_sample2],
  //   [3, trace1_sample3, trace2_sample3],
  // ]
  var data = [];
  for (var i = 0; i < max_samples; i++) {
    var i_samples = [i];

    for (t in selected_traces) {
      if (i < selected_traces[t].length) {
        i_samples.push(selected_traces[t][i]);
      } else {
        i_samples.push(0);
      }
    }

    data.push(i_samples);
  }

  var labels = ["sample"].concat(Object.keys(selected_traces));
  trace_dygraph = new Dygraph(document.getElementById("trace_plot"), data, {
    legend: "always",
    animatedZooms: true,
    title: "Power trace",
    labels: labels,
  });
};

var LoadTraceData = function (trace) {
  $.ajax({
    url: "/data/" + trace,
    method: "GET",
    dataType: "json",
    success: function (d) {
      selected_traces[trace] = d;
      PlotTraceData();
    },
  });
};

var LoadTraces = function () {
  if (trace_dygraph) {
    trace_dygraph.destroy();
    trace_dygraph = null;
    selected_traces = {};
  }
  $.ajax({
    url: "/data",
    method: "GET",
    dataType: "json",
    success: function (d) {
      // Automatically load the first trace.
      if (d["Traces"].length > 0) {
        d["Traces"][0]["Selected"] = true;
        LoadTraceData(d["Traces"][0]["Id"]);
      }
      $("#pk").text(d["Pk"]);
      $("#traces").bootstrapTable("load", d["Traces"]);
    },
    error: function () {
      $("#traces").bootstrapTable("load", []);
    },
  });
};


$(document).ready(function () {
  "use strict";
  $("#traces").bootstrapTable({
    onCheck: function (row, elm) {
      LoadTraceData(row.Id);
    },
    onUncheck: function (row, elm) {
      delete selected_traces[row.Id];
      PlotTraceData();
    },
    onClickRow: function (row, elm, field) {
      if (row.Selected) {
        delete selected_traces[row.Id];
        PlotTraceData();
      } else {
        LoadTraceData(row.Id);
      }
    },
    onCheckAll: function (rows_after, rows_before) {
      rows_after.forEach(function (row, i) {
        if (!(row.Id in selected_traces)) {
          LoadTraceData(row.Id);
        }
      });
    },
    onUncheckAll: function (rows_after, rows_before) {
      rows_before.forEach(function (row, i) {
        if (row.Id in selected_traces) {
          delete selected_traces[row.Id];
          PlotTraceData();
        }
      });
    },
  });
  feather.replace();
  LoadTraces();
});
