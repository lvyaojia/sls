#!/usr/bin/env python
#encoding: utf-8

# Copyright (C) Alibaba Cloud Computing
# All rights reserved.

from aliyun.log.util import Util
from aliyun.log.logresponse import LogResponse
from aliyun.log.shipper_config import ShipperTask


class ListShipperResponse(LogResponse) : 
    def __init__(self, resp, header) : 
        LogResponse.__init__(self, header)
        self.count =  resp['count']
        self.total = resp['total']
        self.shipper_names = resp['shipper']
        
    def get_shipper_count(self) : 
        return self.count

    def get_shipper_total(self) : 
        return self.total

    def get_shipper_names(self) : 
        return self.shipper_names

    def log_print(self) : 
        print 'ListShipperResponse:'
        print 'shipper count : ' + str(self.count)
        print 'shipper total : ' + str(self.total)
        print 'shipper names : ' + str(self.shipper_names)

class GetShipperTasksResponse(LogResponse) :
    def __init__(self, resp, header) : 
        LogResponse.__init__(self, header)
        self.count = resp['count']
        self.total = resp['total']
        self.running_count = resp['statistics']['running']
        self.success_count = resp['statistics']['success']
        self.fail_count = resp['statistics']['fail']
        self.tasks = []
        for task_res in resp['tasks'] : 
            task = ShipperTask(task_res['id'], task_res['taskStatus'] , task_res['taskMessage'], task_res['taskCreateTime'],
                    task_res['taskLastDataReceiveTime'], task_res['taskFinishTime'])
            self.tasks.append(task)

    def get_task_count(self) : 
        return self.count

    def get_task_total(self) : 
        return self.total

    def get_running_task_count(self) : 
        return self.running_count

    def get_success_task_count(self) : 
        return self.success_count

    def get_fail_task_count(self) : 
        return self.fail_count


    def _get_task_ids(self, status) : 
        task_ids = []
        for task in self.tasks : 
            if task.task_status == status : 
                task_ids.append(task.task_id)
        return task_ids

    def get_fail_task_ids(self):
        return self._get_task_ids("fail")

    def get_running_task_ids(self):
        return self._get_task_ids("running")

    def get_running_task_ids(self):
        return self._get_task_ids("success")
    
    def get_taks(self) : 
        return self.tasks

    def log_print(self) : 
        print 'GetShipperTasksResponse:'
        print 'ship count : ' + str(self.count)
        print 'ship total : ' + str(self.total)
        print 'ship running_count : ' + str(self.running_count)
        print 'ship success_count : ' + str(self.success_count)
        print 'ship fail_count : ' + str(self.fail_count)
        print 'ship taks : '
        for task in self.tasks : 
            print str(task.to_json())


def RetryShipperTasksResponse(LogResponse) : 
    def __init__(self, header) : 
        LogResponse.__init__(self, header)

    def log_print(self) : 
        print 'RetryShipperTasksResponse' 


        
        
