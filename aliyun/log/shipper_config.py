#!/usr/bin/env python
#encoding: utf-8

# Copyright (C) Alibaba Cloud Computing
# All rights reserved.

try:
    import json
except ImportError:
    import simplejson as json

class ShipperTask:

    """init a shipper task
    :type task_id: string
    :param task_id: the task id

    :type task_status: string
    :param task_status: one of ['success', 'running', 'fail']

    :type task_message : string
    :param task_message: the error message of task_status is 'fail'

    :type task_create_time :  int
    :param task_create_time : the task create time (timestamp from 1970.1.1)

    :type task_last_data_receive_time: int
    :param task_last_data_receive_time: last log data receive time (timestamp)

    :type task_finish_time: int
    :param task_finish_time: the task finish time (timestamp)
    """
    def __init__(self, task_id, task_status , task_message, task_create_time, task_last_data_receive_time, task_finish_time) : 
        self.task_id = task_id
        self.task_status = task_status
        self.task_message = task_message
        self.task_create_time = task_create_time
        self.task_last_data_receive_time = task_last_data_receive_time
        self.task_finish_time = task_finish_time

    def to_json(self) : 
        json_value = {}
        json_value['id'] = self.task_id
        json_value['taskStatus'] = self.task_status
        json_value['taskMessage'] = self.task_message
        json_value['taskCreateTime'] = self.task_create_time
        json_value['taskLastDataReceiveTime'] = self.task_last_data_receive_time
        json_value['taskFinishTime'] = self.task_finish_time
        return json_value
    
