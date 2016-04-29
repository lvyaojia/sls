#!/usr/bin/env python
# encoding: utf-8

# Copyright (C) Alibaba Cloud Computing
# All rights reserved.

import sys
import requests
try:
    import json
except ImportError:
    import simplejson as json
from datetime import datetime
from log_logs_pb2 import LogGroup
from aliyun.log.util import Util
from aliyun.log.logexception import LogException
from aliyun.log.getlogsresponse import GetLogsResponse
from aliyun.log.putlogsresponse import PutLogsResponse
from aliyun.log.listtopicsresponse import ListTopicsResponse
from aliyun.log.listlogstoresresponse import ListLogstoresResponse
from aliyun.log.gethistogramsresponse import GetHistogramsResponse

from aliyun.log.logstore_config_response import CreateLogStoreResponse
from aliyun.log.logstore_config_response import DeleteLogStoreResponse
from aliyun.log.logstore_config_response import GetLogStoreResponse
from aliyun.log.logstore_config_response import UpdateLogStoreResponse
from aliyun.log.logstore_config_response import ListLogStoreResponse

from aliyun.log.pulllog_response import PullLogResponse
from aliyun.log.cursor_response import GetCursorResponse

from aliyun.log.index_config_response import CreateIndexResponse
from aliyun.log.index_config_response import UpdateIndexResponse
from aliyun.log.index_config_response import DeleteIndexResponse
from aliyun.log.index_config_response import GetIndexResponse

from aliyun.log.logtail_config_response import CreateLogtailConfigResponse
from aliyun.log.logtail_config_response import UpdateLogtailConfigResponse
from aliyun.log.logtail_config_response import DeleteLogtailConfigResponse
from aliyun.log.logtail_config_response import GetLogtailConfigResponse
from aliyun.log.logtail_config_response import ListLogtailConfigResponse

from aliyun.log.machinegroup_response import CreateMachineGroupResponse
from aliyun.log.machinegroup_response import UpdateMachineGroupResponse
from aliyun.log.machinegroup_response import DeleteMachineGroupResponse
from aliyun.log.machinegroup_response import GetMachineGroupResponse
from aliyun.log.machinegroup_response import ListMachineGroupResponse

from aliyun.log.machinegroup_response import ListMachinesResponse
from aliyun.log.machinegroup_response import ApplyConfigToMachineGroupResponse
from aliyun.log.machinegroup_response import RemoveConfigToMachineGroupResponse
from aliyun.log.machinegroup_response import GetMachineGroupAppliedConfigResponse
from aliyun.log.machinegroup_response import GetConfigAppliedMachineGroupsResponse

from aliyun.log.shard_response import ListShardResponse
from aliyun.log.shard_response import DeleteShardResponse

from aliyun.log.shipper_response import ListShipperResponse
from aliyun.log.shipper_response import GetShipperTasksResponse
from aliyun.log.shipper_response import RetryShipperTasksResponse

CONNECTION_TIME_OUT = 20
API_VERSION = '0.6.0'
USER_AGENT = 'log-python-sdk-v-0.6.1'

"""
LogClient class is the main class in the SDK. It can be used to communicate with 
log service server to put/get data.

:Author: log_dev
"""

class LogClient(object):
    """ Construct the LogClient with endpoint, accessKeyId, accessKey.
    
    :type endpoint: string
    :param endpoint: log service host name, for example, http://ch-hangzhou.sls.aliyuncs.com
    
    :type accessKeyId: string
    :param accessKeyId: aliyun accessKeyId
    
    :type accessKey: string
    :param accessKey: aliyun accessKey
    """
    
    __version__ = API_VERSION
    Version = __version__
    
    def __init__(self, endpoint, accessKeyId, accessKey,securityToken = None):
        if isinstance(endpoint, unicode): # ensure is ascii str
            endpoint = endpoint.encode('ascii')
        if isinstance(accessKeyId, unicode):
            accessKeyId = accessKeyId.encode('ascii')
        if isinstance(accessKey, unicode):
            accessKey = accessKey.encode('ascii')
        self._isRowIp = True
        self._port = 80
        self._setendpoint(endpoint)
        self._accessKeyId = accessKeyId
        self._accessKey = accessKey
        self._timeout = CONNECTION_TIME_OUT
        self._source = Util.get_host_ip(self._logHost)
        self._securityToken = securityToken;

    def _setendpoint(self, endpoint):
        pos = endpoint.find('://')
        if pos != -1:
            endpoint = endpoint[pos + 3:]  # strip http://
        pos = endpoint.find('/')
        if pos != -1:
            endpoint = endpoint[:pos]
        pos = endpoint.find(':')
        if pos != -1:
            self._port = int(endpoint[pos + 1:])
            endpoint = endpoint[:pos]
        self._isRowIp = Util.is_row_ip(endpoint)
        self._logHost = endpoint
        self._endpoint = endpoint + ':' + str(self._port)

    def _getGMT(self):
        return datetime.utcnow().strftime('%a, %d %b %Y %H:%M:%S GMT')

    def _loadJson(self, respText, requestId):
        if not respText:
            return None
        try:
            return json.loads(respText)
        except:
            raise LogException('BadResponse', 
                               'Bad json format:\n%s' % respText,
                               requestId)
    
    def _getHttpResponse(self, method, url, params, body, headers): # ensure method, url, body is str
        try : 
            headers['User-Agent'] = USER_AGENT
            r = None
            if method.lower() == 'get' : 
                r = requests.get(url, params = params, data = body, headers = headers, timeout = self._timeout)
            elif method.lower() == 'post': 
                r = requests.post(url, params = params, data = body, headers = headers, timeout = self._timeout)
            elif method.lower() == 'put': 
                r = requests.put(url, params = params, data = body, headers = headers, timeout = self._timeout)
            elif method.lower() == 'delete': 
                r = requests.delete(url, params = params, data = body, headers = headers, timeout = self._timeout)
            return (r.status_code, r.content, r.headers) 
        except Exception, ex:
            raise LogException('LogRequestError', str(ex))
    
    def _sendRequest(self, method, url, params, body, headers, respons_body_type = 'json'):
        (status, respText, respHeader) = self._getHttpResponse(method, url, params, body, headers)
        header = {}
        for key, value in respHeader.items():
            header[key] = value
        
        requestId = header['x-log-requestid'] if 'x-log-requestid' in header else ''
        exJson = None

        header = Util.convert_unicode_to_str(header)
        if status == 200 : 
            if respons_body_type == 'json' : 
                exJson = self._loadJson(respText, requestId)
                #exJson = Util.convert_unicode_to_str(exJson)
                return (exJson, header)
            else : 
                return (respText, header)
            
        exJson = self._loadJson(respText.encode('utf-8'), requestId)
        exJson = Util.convert_unicode_to_str(exJson)

        if 'errorCode' in exJson and 'errorMessage' in exJson:
            raise LogException(exJson['errorCode'], exJson['errorMessage'], requestId)
        else:
            exJson = '. Return json is '+str(exJson) if exJson else '.'
            raise LogException('LogRequestError', 
                               'Request is failed. Http code is '+str(status)+exJson, requestId)
    
    def _send(self, method, project, body, resource, params, headers, respons_body_type ='json'):
        if body:
            headers['Content-Length'] = len(body)
            headers['Content-MD5'] = Util.cal_md5(body)
        else:
            headers['Content-Length'] = 0
            headers["x-log-bodyrawsize"] = 0
        
        headers['x-log-apiversion'] = API_VERSION
        headers['x-log-signaturemethod'] = 'hmac-sha1'
        url = ''
        if self._isRowIp:
            url = "http://" + self._endpoint
        else:
            url = "http://" + project + "." + self._endpoint
        headers['Host'] = project + "." + self._logHost
        headers['Date'] = self._getGMT()
        if self._securityToken != None and self._securityToken != "" : 
            headers["x-acs-security-token"] = self._securityToken
        
        signature = Util.get_request_authorization(method, resource,
            self._accessKey, params, headers)
        headers['Authorization'] = "LOG " + self._accessKeyId + ':' + signature
        url = url + resource
        return self._sendRequest(method, url, params, body, headers, respons_body_type)
    
    def get_unicode(self, key):
        if isinstance(key, str):
            key = unicode(key, 'utf-8')
        return key
    
        
    def put_logs(self, request):
        """ Put logs to log service.
        Unsuccessful opertaion will cause an LogException.
        
        :type request: PutLogsRequest
        :param request: the PutLogs request parameters class
        
        :return: PutLogsResponse
        
        :raise: LogException
        """
        if len(request.get_log_items()) > 4096:
            raise LogException('InvalidLogSize', 
                            "logItems' length exceeds maximum limitation: 4096 lines.")
        logGroup = LogGroup()
        logGroup.Topic = request.get_topic()
        if request.get_source():
            logGroup.Source = request.get_source()
        else:
            if self._source=='127.0.0.1':
                self._source = Util.get_host_ip(request.get_project() + '.' + self._logHost)
            logGroup.Source = self._source
        for logItem in request.get_log_items():
            log = logGroup.Logs.add()
            log.Time = logItem.get_time()
            contents = logItem.get_contents()
            for key, value in contents:
                content = log.Contents.add()
                content.Key = self.get_unicode(key)
                content.Value = self.get_unicode(value)
        body = logGroup.SerializeToString()
        if len(body) > 3 * 1024 * 1024:  # 3 MB
            raise LogException('InvalidLogSize', 
                            "logItems' size exceeds maximum limitation: 3 MB.")
        
        headers = {}
        headers['x-log-bodyrawsize'] = len(body)
        headers['Content-Type'] = 'application/x-protobuf'

        params = {}
        logstore = request.get_logstore()
        project = request.get_project()
        resource = '/logstores/' + logstore
        if request.get_hash_key() is not None:
            resource = '/logstores/' + logstore+"/shards/route"
            params["key"] = request.get_hash_key() 
        else:
            resource = '/logstores/' + logstore+"/shards/lb"

        respHeaders = self._send('POST', project, body, resource, params, headers)
        return PutLogsResponse(respHeaders[1])
    
    def list_logstores(self, request):
        """ List all logstores of requested project.
        Unsuccessful opertaion will cause an LogException.
        
        :type request: ListLogstoresRequest
        :param request: the ListLogstores request parameters class.
        
        :return: ListLogStoresResponse
        
        :raise: LogException
        """
        headers = {}
        params = {}
        resource = '/logstores'
        project = request.get_project()
        (resp, header) = self._send("GET", project, None, resource, params, headers)
        return ListLogstoresResponse(resp, header)
    
    def list_topics(self, request):
        """ List all topics in a logstore.
        Unsuccessful opertaion will cause an LogException.
        
        :type request: ListTopicsRequest
        :param request: the ListTopics request parameters class.
        
        :return: ListTopicsResponse
        
        :raise: LogException
        """
        headers = {}
        params = {}
        if request.get_token()!=None:
            params['token'] = request.get_token()
        if request.get_line()!=None:
            params['line'] = request.get_line()
        params['type'] = 'topic'
        logstore = request.get_logstore()
        project = request.get_project()
        resource = "/logstores/" + logstore
        (resp, header) = self._send("GET", project, None, resource, params, headers)
        return ListTopicsResponse(resp, header)

    def get_histograms(self, request):
        """ Get histograms of requested query from log service.
        Unsuccessful opertaion will cause an LogException.
        
        :type request: GetHistogramsRequest
        :param request: the GetHistograms request parameters class.
        
        :return: GetHistogramsResponse
        
        :raise: LogException
        """
        headers = {}
        params = {}
        if request.get_topic()!=None:
            params['topic'] = request.get_topic()
        if request.get_from()!=None:
            params['from'] = request.get_from()
        if request.get_to()!=None:
            params['to'] = request.get_to()
        if request.get_query()!=None:
            params['query'] = request.get_query()
        params['type'] = 'histogram'
        logstore = request.get_logstore()
        project = request.get_project()
        resource = "/logstores/" + logstore
        (resp, header) = self._send("GET", project, None, resource, params, headers)
        return GetHistogramsResponse(resp, header)

    def get_logs(self, request):
        """ Get logs from log service.
        Unsuccessful opertaion will cause an LogException.
        
        :type request: GetLogsRequest
        :param request: the GetLogs request parameters class.
        
        :return: GetLogsResponse
        
        :raise: LogException
        """
        headers = {}
        params = {}
        if request.get_topic()!=None:
            params['topic'] = request.get_topic()
        if request.get_from()!=None:
            params['from'] = request.get_from()
        if request.get_to()!=None:
            params['to'] = request.get_to()
        if request.get_query()!=None:
            params['query'] = request.get_query()
        params['type'] = 'log'
        if request.get_line()!=None:
            params['line'] = request.get_line()
        if request.get_offset()!=None:
            params['offset'] = request.get_offset()
        if request.get_reverse()!=None:
            params['reverse'] = 'true' if request.get_reverse() else 'false'
        logstore = request.get_logstore()
        project = request.get_project()
        resource = "/logstores/" + logstore
        (resp, header) = self._send("GET", project, None, resource, params, headers)
        return GetLogsResponse(resp, header)
    

    def get_cursor(self, project_name, logstore_name, shard_id, start_time) : 
        """ Get cursor from log service for batch pull logs
        Unsuccessful opertaion will cause an LogException.
        :type project_name: string
        :param project_name: the Project name 

        :type logstore_name: string
        :param logstore_name: the logstore name

        :type shard_id: int
        :param shard_id: the shard id

        :type start_time: int
        :param start_time: the start time of cursor, e.g 1441093445

        :return: GetLogsResponse
        
        :raise: LogException
        """

        headers = {}
        headers['Content-Type'] = 'application/json'
        params = {}
        resource = "/logstores/" + logstore_name + "/shards/" + str(shard_id)
        params['type'] = 'cursor'
        params['from'] = str(start_time)
        
        (resp, header) = self._send("GET", project_name, None, resource, params, headers)
        return GetCursorResponse(resp, header)


    def get_begin_cursor(self, project_name, logstore_name, shard_id) :
        """ Get begin cursor from log service for batch pull logs
        Unsuccessful opertaion will cause an LogException.
        :type project_name: string
        :param project_name: the Project name 

        :type logstore_name: string
        :param logstore_name: the logstore name

        :type shard_id: int
        :param shard_id: the shard id

        :return: GetLogsResponse
        
        :raise: LogException
        """
        return self.get_cursor(project_name, logstore_name, shard_id, "begin")

    def get_end_cursor(self, project_name, logstore_name, shard_id) : 
        """ Get end cursor from log service for batch pull logs
        Unsuccessful opertaion will cause an LogException.
        :type project_name: string
        :param project_name: the Project name 

        :type logstore_name: string
        :param logstore_name: the logstore name

        :type shard_id: int
        :param shard_id: the shard id

        :return: GetLogsResponse
        
        :raise: LogException
        """
        return self.get_cursor(project_name, logstore_name, shard_id, "end")

    def pull_logs(self, project_name, logstore_name, shard_id, cursor, count = 1000):
        """ batch pull log data from log service
        Unsuccessful opertaion will cause an LogException.
        :type project_name: string
        :param project_name: the Project name 

        :type logstore_name: string
        :param logstore_name: the logstore name

        :type shard_id: int
        :param shard_id: the shard id

        :type cursor: string
        :param cursor: the start to cursor to get data

        :type count: int
        :param count: the required pull log package count, default 1000 packages

        :return: PullLogResponse
        
        :raise: LogException
        """
        headers = {}
        headers['Accept-Encoding'] = ''
        headers['Accept'] = 'application/x-protobuf'
        
        params = {}
        resource = "/logstores/" + logstore_name + "/shards/" + str(shard_id)
        params['type'] = 'log'
        params['cursor'] = cursor
        params['count'] = str(count)
        (resp, header) = self._send("GET", project_name, None, resource, params, headers, "binary")
        return PullLogResponse(resp, header)
    


    def create_logstore(self, project_name, logstore_name, ttl, shard_count):
        """ create log store 
        Unsuccessful opertaion will cause an LogException.
        :type project_name: string
        :param project_name: the Project name 

        :type logstore_name: string
        :param logstore_name: the logstore name

        :type ttl: int
        :param ttl: the life cycle of log in the logstore in days

        :type shard_count: int
        :param shard_count: the shard count of the logstore to create


        :return: CreateLogStoreResponse
        
        :raise: LogException
        """
        headers = {}
        params = {}
        headers["x-log-bodyrawsize"] = 0
        headers["Content-Type"] = "application/json"
        resource = "/logstores"
        body = {}
        body["logstoreName"] = logstore_name.encode("utf-8");
        body["ttl"] = (int)(ttl);
        body["shardCount"] = (int)(shard_count);
        body_str = json.dumps(body);
        (resp, header) = self._send("POST", project_name, body_str, resource, params, headers)
        return CreateLogStoreResponse(header)


    def delete_logstore(self, project_name, logstore_name):
        """ delete log store
        Unsuccessful opertaion will cause an LogException.

        :type project_name: string
        :param project_name: the Project name 

        :type logstore_name: string
        :param logstore_name: the logstore name

        :return: DeleteLogStoreResponse
        
        :raise: LogException
        """
        headers = {}
        params = {}
        resource = "/logstores/" + logstore_name
        (resp, header) = self._send("DELETE", project_name, None, resource, params, headers)
        return DeleteLogStoreResponse(header)

    def get_logstore(self, project_name, logstore_name):
        """ get the logstore meta info
        Unsuccessful opertaion will cause an LogException.

        :type project_name: string
        :param project_name: the Project name 

        :type logstore_name: string
        :param logstore_name: the logstore name

        :return: GetLogStoreResponse
        
        :raise: LogException
        """

        headers = {}
        params = {}
        resource = "/logstores/" + logstore_name
        (resp, header) = self._send("GET", project_name, None, resource, params, headers)
        return GetLogStoreResponse(resp, header)

    def update_logstore(self, project_name, logstore_name, ttl, shard_count):
        """ 
        update the logstore meta info
        Unsuccessful opertaion will cause an LogException.

        :type project_name: string
        :param project_name: the Project name 

        :type logstore_name: string
        :param logstore_name: the logstore name

        :type ttl: int
        :param ttl: the life cycle of log in the logstore in days

        :type shard_count: int
        :param shard_count: the shard count of the logstore to create

        :return: UpdateLogStoreResponse
        
        :raise: LogException
        """

        headers = {}
        headers["x-log-bodyrawsize"] = 0
        headers["Content-Type"] = "application/json"
        params = {}
        resource = "/logstores/" + logstore_name
        body = {}
        body["logstoreName"] = logstore_name
        body["ttl"] = (int)(ttl);
        body["shardCount"] = (int)(shard_count);
        body_str = json.dumps(body);
        (resp, header) = self._send("PUT", project_name, body_str, resource, params, headers)
        return UpdateLogStoreResponse(header)


    def list_logstore(self, project_name, logstore_name_pattern = None, offset = 0, size = 100) :
        """ list the logstore in a project
        Unsuccessful opertaion will cause an LogException.

        :type project_name: string
        :param project_name: the Project name 

        :type logstore_name_pattern: string
        :param logstore_name_pattern: the sub name logstore, used for the server to return logstore names contain this sub name

        :type offset: int
        :param offset: the offset of all the matched names

        :type size: int
        :param size: the max return names count

        :return: ListLogStoreResponse
        
        :raise: LogException
        """
        headers = {}
        params = {}
        resource = "/logstores"
        if logstore_name_pattern != None :
            params['logstorename'] = logstore_name_pattern
        params['offset'] = str(offset)
        params['size'] = str(size)
        (resp, header) = self._send("GET", project_name, None, resource, params, headers)
        return ListLogStoreResponse(resp, header)


    def list_shards(self, project_name, logstore_name) :
        """ list the shard meta of a logstore
        Unsuccessful opertaion will cause an LogException.

        :type project_name: string
        :param project_name: the Project name 

        :type logstore_name: string
        :param logstore_name: the logstore name

        :return: ListShardResponse
        
        :raise: LogException
        """
        headers = {}
        params = {}
        resource = "/logstores/" + logstore_name + "/shards"
        (resp, header) = self._send("GET", project_name, None, resource, params, headers)
        return ListShardResponse(resp, header)
    def split_shard(self,project_name,logstore_name,shardId,split_hash):
        """ split a  readwrite shard into two shards
        Unsuccessful opertaion will cause an LogException.

        :type project_name: string
        :param project_name: the Project name 

        :type logstore_name: string
        :param logstore_name: the logstore name
        
        :type shardId: int
        :param shardId : the shard id

        :type split_hash: string
        :param split_hash: the internal hash between the shard begin and end hash

        :return: ListShardResponse
        
        :raise: LogException
        """

        headers = {}
        params = {"action":"split","key":split_hash}
        resource = "/logstores/"+logstore_name+"/shards/"+str(shardId);
        (resp,header) =  self._send("POST",project_name,None,resource,params,headers);
        return ListShardResponse(resp,header);

    def merge_shard(self,project_name,logstore_name,shardId):
        """ split two adjacent  readwrite hards into one shards
        Unsuccessful opertaion will cause an LogException.

        :type project_name: string
        :param project_name: the Project name 

        :type logstore_name: string
        :param logstore_name: the logstore name
        
        :type shardId: int
        :param shardId : the shard id of the left shard, server will determine the right adjacent  shardId

        :return: ListShardResponse
        
        :raise: LogException
        """
        headers = {}
        params = {"action":"merge"}
        resource = "/logstores/"+logstore_name+"/shards/"+str(shardId);
        (resp,header) =  self._send("POST",project_name,None,resource,params,headers);
        return ListShardResponse(resp,header);

    def delete_shard(self,project_name,logstore_name,shardId):
        """ delete a readonly shard 
        Unsuccessful opertaion will cause an LogException.

        :type project_name: string
        :param project_name: the Project name 

        :type logstore_name: string
        :param logstore_name: the logstore name
        
        :type shardId: int
        :param shardId : the read only shard id  

        :return: ListShardResponse
        
        :raise: LogException
        """
        headers = {}
        params = {}
        resource = "/logstores/"+logstore_name+"/shards/"+str(shardId);
        (resp,header) =  self._send("DELETE",project_name,None,resource,params,headers);
        return DeleteShardResponse(header);



    def create_index(self, project_name, logstore_name, index_detail) : 
        """ create index for a logstore
        Unsuccessful opertaion will cause an LogException.

        :type project_name: string
        :param project_name: the Project name 

        :type logstore_name: string
        :param logstore_name: the logstore name

        :type index_detail: index_config.IndexConfig
        :param index_detail: the index config detail used to create index

        :return: CreateIndexResponse
        
        :raise: LogException
        """
        headers = {}
        params = {}
        resource = "/logstores/" + logstore_name + "/index"
        headers['Content-Type'] = 'application/json'
        body = json.dumps(index_detail.to_json())
        headers['x-log-bodyrawsize'] = len(body)

        (resp, header) = self._send("POST", project_name, body, resource, params, headers)
        return CreateIndexResponse(header)

    def update_index(self, project_name, logstore_name, index_detail) : 
        """ update index for a logstore
        Unsuccessful opertaion will cause an LogException.

        :type project_name: string
        :param project_name: the Project name 

        :type logstore_name: string
        :param logstore_name: the logstore name

        :type index_detail: index_config.IndexConfig
        :param index_detail: the index config detail used to update index

        :return: UpdateIndexResponse
        
        :raise: LogException
        """

        headers = {}
        params = {}
        resource = "/logstores/" + logstore_name + "/index"
        headers['Content-Type'] = 'application/json'
        body = json.dumps(index_detail.to_json())
        headers['x-log-bodyrawsize'] = len(body)

        (resp, header) = self._send("PUT", project_name, body, resource, params, headers)
        return UpdateIndexResponse(header)
    
    def delete_index(self, project_name, logstore_name) :
        """ delete index of a logstore
        Unsuccessful opertaion will cause an LogException.

        :type project_name: string
        :param project_name: the Project name 

        :type logstore_name: string
        :param logstore_name: the logstore name

        :return: DeleteIndexResponse
        
        :raise: LogException
        """

        headers = {}
        params = {}
        resource = "/logstores/" + logstore_name + "/index"
        (resp, header) = self._send("DELETE", project_name, None, resource, params, headers)
        return DeleteIndexResponse(header)

    def get_index_config(self, project_name , logstore_name) :
        """ get index config detail of a logstore
        Unsuccessful opertaion will cause an LogException.

        :type project_name: string
        :param project_name: the Project name 

        :type logstore_name: string
        :param logstore_name: the logstore name

        :return: GetIndexResponse
        
        :raise: LogException
        """

        headers = {}
        params = {}
        resource = "/logstores/" + logstore_name + "/index"
        (resp, header) = self._send("GET", project_name, None, resource, params, headers)
        return GetIndexResponse(resp, header)


    def create_logtail_config(self, project_name, config_detail) : 
        """ create logtail config in a project
        Unsuccessful opertaion will cause an LogException.

        :type project_name: string
        :param project_name: the Project name 

        :type config_detail: logtail_config_detail.CommonRegLogConfigDetail or logtail_config_detail.ApsaraLogConfigDetail
        :param config_detail: the logtail config detail info, the CommonRegLogConfigDetail is used to create common regex logs ,the ApsaraLogConfigDetail is used to create apsara log

        :return: CreateLogtailConfigResponse
        
        :raise: LogException
        """

        headers = {}
        params = {}
        resource = "/configs"
        headers['Content-Type'] = 'application/json'
        body = json.dumps(config_detail.to_json())
        headers['x-log-bodyrawsize'] = len(body)
        (resp, headers) = self._send("POST", project_name, body, resource, params, headers)
        return CreateLogtailConfigResponse(headers)

    def update_logtail_config(self, project_name, config_detail) : 
        """ update logtail config in a project
        Unsuccessful opertaion will cause an LogException.

        :type project_name: string
        :param project_name: the Project name 

        :type config_detail: logtail_config_detail.CommonRegLogConfigDetail or logtail_config_detail.ApsaraLogConfigDetail
        :param config_detail: the logtail config detail info, the CommonRegLogConfigDetail is used to create common regex logs, the ApsaraLogConfigDetail is used to create apsara log

        :return: UpdateLogtailConfigResponse
        
        :raise: LogException
        """

        headers = {}
        params = {}
        resource = "/configs/" + config_detail.config_name
        headers['Content-Type'] = 'application/json'
        body = json.dumps(config_detail.to_json())
        headers['x-log-bodyrawsize'] = len(body)
        (resp, headers) = self._send("PUT", project_name, body, resource, params, headers)
        return UpdateLogtailConfigResponse(headers)


    def delete_logtail_config(self, project_name, config_name):
        """ delete logtail config in a project
        Unsuccessful opertaion will cause an LogException.

        :type project_name: string
        :param project_name: the Project name 

        :type config_name: string
        :param config_name: the logtail config name

        :return: DeleteLogtailConfigResponse
        
        :raise: LogException
        """

        headers = {}
        params = {}
        resource = "/configs/" + config_name
        (resp, headers) = self._send("DELETE", project_name, None, resource, params, headers)
        return DeleteLogtailConfigResponse(headers)


    def get_logtail_config(self, project_name, config_name) : 
        """ get logtail config in a project
        Unsuccessful opertaion will cause an LogException.

        :type project_name: string
        :param project_name: the Project name 

        :type config_name: string
        :param config_name: the logtail config name

        :return: GetLogtailConfigResponse
        
        :raise: LogException
        """
        headers = {}
        params = {}
        resource = "/configs/" + config_name
        (resp, headers) = self._send("GET", project_name, None, resource, params, headers)
        return GetLogtailConfigResponse(resp, headers)


    def list_logtail_config(self, project_name, offset = 0, size = 100) :
        """ list logtail config name in a project
        Unsuccessful opertaion will cause an LogException.

        :type project_name: string
        :param project_name: the Project name 

        :type offset: int
        :param offset: the offset of all config names

        :type size: int
        :param size: the max return names count

        :return: ListLogtailConfigResponse
        
        :raise: LogException
        """
        headers = {}
        params = {}
        resource = "/configs"
        params['offset'] = str(offset)
        params['size'] = str(size)
        (resp, header) = self._send("GET", project_name, None, resource, params, headers)
        return ListLogtailConfigResponse(resp, header)


    def create_machine_group(self, project_name, group_detail) : 
        """ create machine group in a project
        Unsuccessful opertaion will cause an LogException.

        :type project_name: string
        :param project_name: the Project name 

        :type group_detail: machine_group_detail.MachineGroupDetail
        :param group_detail: the machine group detail config

        :return: CreateMachineGroupResponse
        
        :raise: LogException
        """

        headers = {}
        params = {}
        resource = "/machinegroups"
        headers['Content-Type'] = 'application/json'
        body = json.dumps(group_detail.to_json())
        headers['x-log-bodyrawsize'] = len(body)
        (resp, headers) = self._send("POST", project_name, body, resource, params, headers)
        return CreateMachineGroupResponse(headers)

    def delete_machine_group(self, project_name, group_name):
        """ delete machine group in a project
        Unsuccessful opertaion will cause an LogException.

        :type project_name: string
        :param project_name: the Project name 

        :type group_name: string
        :param group_name: the group name

        :return: DeleteMachineGroupResponse
        
        :raise: LogException
        """

        headers = {}
        params = {}
        resource = "/machinegroups/" + group_name
        (resp, headers) = self._send("DELETE", project_name, None, resource, params, headers)
        return DeleteMachineGroupResponse(headers)

    def update_machine_group(self, project_name, group_detail) : 
        """ update machine group in a project
        Unsuccessful opertaion will cause an LogException.

        :type project_name: string
        :param project_name: the Project name 

        :type group_detail: machine_group_detail.MachineGroupDetail
        :param group_detail: the machine group detail config

        :return: UpdateMachineGroupResponse
        
        :raise: LogException
        """

        headers = {}
        params = {}
        resource = "/machinegroups/" + group_detail.group_name
        headers['Content-Type'] = 'application/json'
        body = json.dumps(group_detail.to_json())
        headers['x-log-bodyrawsize'] = len(body)
        (resp, headers) = self._send("PUT", project_name, body, resource, params, headers)
        return UpdateMachineGroupResponse(headers)

    def get_machine_group(self, project_name, group_name) : 
        """ get machine group in a project
        Unsuccessful opertaion will cause an LogException.

        :type project_name: string
        :param project_name: the Project name 

        :type group_name: string
        :param group_name: the group name to get

        :return: GetMachineGroupResponse
        
        :raise: LogException
        """

        headers = {}
        params = {}
        resource = "/machinegroups/" + group_name
        (resp, headers) = self._send("GET", project_name, None, resource, params, headers)
        return GetMachineGroupResponse(resp, headers)

    def list_machine_group(self, project_name, offset = 0, size = 100) :
        """ list machine group names in a project
        Unsuccessful opertaion will cause an LogException.

        :type project_name: string
        :param project_name: the Project name 

        :type offset: int
        :param offset: the offset of all group name

        :type size: int
        :param size: the max return names count

        :return: ListMachineGroupResponse
        
        :raise: LogException
        """

        headers = {}
        params = {}
        resource = "/machinegroups"
        params['offset'] = str(offset)
        params['size'] = str(size)
        (resp, header) = self._send("GET", project_name, None, resource, params, headers)
        return ListMachineGroupResponse(resp, header)

    def list_machines(self, project_name, group_name, offset = 0, size = 100) : 
        """ list machines in a machine group
        Unsuccessful opertaion will cause an LogException.

        :type project_name: string
        :param project_name: the Project name 
        
        :type group_name: string
        :param group_name: the group name to list

        :type offset: int
        :param offset: the offset of all group name

        :type size: int
        :param size: the max return names count

        :return: ListMachinesResponse
        
        :raise: LogException
        """

        headers = {}
        params = {}
        resource = "/machinegroups/" + group_name + "/machines"
        params['offset'] = str(offset)
        params['size'] = str(size)
        (resp, header) = self._send("GET", project_name, None, resource, params, headers)
        return ListMachinesResponse(resp, header)

    def apply_config_to_machine_group(self, project_name, config_name, group_name) : 
        """ apply a logtail config to a machine group
        Unsuccessful opertaion will cause an LogException.

        :type project_name: string
        :param project_name: the Project name 

        :type config_name: string
        :param config_name: the logtail config name to apply
        
        :type group_name: string
        :param group_name: the machine group name 

        :return: ApplyConfigToMachineGroupResponse
        
        :raise: LogException
        """
        headers = {}
        params = {}
        resource = "/machinegroups/" + group_name + "/configs/" + config_name
        (resp, header) = self._send("PUT", project_name, None, resource, params, headers)
        return ApplyConfigToMachineGroupResponse(header)

    def remove_config_to_machine_group(self, project_name, config_name, group_name) : 
        """ remove a logtail config to a machine group
        Unsuccessful opertaion will cause an LogException.

        :type project_name: string
        :param project_name: the Project name 

        :type config_name: string
        :param config_name: the logtail config name to apply
        
        :type group_name: string
        :param group_name: the machine group name 

        :return: RemoveConfigToMachineGroupResponse
        
        :raise: LogException
        """
        headers = {}
        params = {}
        resource = "/machinegroups/" + group_name + "/configs/" + config_name
        (resp, header) = self._send("DELETE", project_name, None, resource, params, headers)
        return RemoveConfigToMachineGroupResponse(header)


    def get_machine_group_applied_configs(self, project_name, group_name):
        """ get the logtail config names applied in a machine group
        Unsuccessful opertaion will cause an LogException.

        :type project_name: string
        :param project_name: the Project name 

        :type group_name: string
        :param group_name: the group name list

        :return: GetMachineGroupAppliedConfigResponse
        
        :raise: LogException
        """

        headers = {}
        params = {}
        resource = "/machinegroups/" + group_name + "/configs"
        (resp, header) = self._send("GET", project_name, None, resource, params, headers)
        return GetMachineGroupAppliedConfigResponse(resp, header)

    def get_config_applied_machine_groups(self, project_name, config_name):
        """ get machine group names where the logtail config applies to
        Unsuccessful opertaion will cause an LogException.

        :type project_name: string
        :param project_name: the Project name 

        :type config_name: string
        :param config_name: the logtail config name used to apply

        :return: GetConfigAppliedMachineGroupsResponse
        
        :raise: LogException
        """

        headers = {}
        params = {}
        resource = "/configs/" + config_name + "/machinegroups"
        (resp, header) = self._send("GET", project_name, None, resource, params, headers)
        return GetConfigAppliedMachineGroupsResponse(resp, header)



    def list_shipper(self, project_name, logstore_name) : 
        """ list  odps/oss shipper
        Unsuccessful opertaion will cause an LogException.

        :type project_name: string
        :param project_name: the Project name 

        :type logstore_name: string
        :param logstore_name: the logstore name

        :return: ListShipperResponse
        
        :raise: LogException
        """
        headers = {}
        params = {}
        resource = "/logstores/" + logstore_name + "/shipper"
        (resp, header) = self._send("GET", project_name, None, resource, params, headers)
        return ListShipperResponse(resp, header)
    
    def get_shipper_tasks(self, project_name, logstore_name, shipper_name, start_time, end_time, status_type = '',  offset = 0, size = 100):
        """ get  odps/oss shipper tasks in a certain time range
        Unsuccessful opertaion will cause an LogException.

        :type project_name: string
        :param project_name: the Project name 

        :type logstore_name: string
        :param logstore_name: the logstore name

        :type shipper_name: string
        :param shipper_name: the shipper name

        :type start_time: int
        :param start_time: the start timestamp

        :type end_time: int
        :param end_time: the end timestamp 

        :type status_type : string
        :param status_type : support one of ['', 'fail', 'success', 'running'] , if the status_type = '' , return all kinds of status type

        :type offset : int
        :param offset : the begin task offset

        :type size : int
        :param size : the needed tasks count 

        :return: ListShipperResponse
        
        :raise: LogException
        """
        headers = {}
        params = {}
        params["from"] = str(int(start_time))
        params["to"] = str(int(end_time))
        params["status"] = status_type
        params["offset"] = str(int(offset))
        params["size"] = str(int(size))
        
        resource = "/logstores/" + logstore_name + "/shipper/" + shipper_name + "/tasks"
        (resp, header) = self._send("GET", project_name, None, resource, params, headers)
        return GetShipperTasksResponse(resp, header)

    def retry_shipper_tasks(self, project_name, logstore_name, shipper_name,  task_list) : 
        """ retry failed tasks , only the failed task can be retried
        Unsuccessful opertaion will cause an LogException.

        :type project_name: string
        :param project_name: the Project name 

        :type logstore_name: string
        :param logstore_name: the logstore name

        :type shipper_name: string
        :param shipper_name: the shipper name

        :type task_list: string array
        :param task_list: the failed task_id list, e.g ['failed_task_id_1', 'failed_task_id_2',...], currently the max retry task count 10 every time 

        :return: RetryShipperTasksResponse
        
        :raise: LogException
        """
        headers = {}
        params = {}
        body = json.dumps(task_list)
        headers['Content-Type'] = 'application/json'
        headers['x-log-bodyrawsize'] = len(body)
        resource = "/logstores/" + logstore_name + "/shipper/" + shipper_name + "/tasks"

        (resp, header) = self._send("PUT", project_name, body, resource, params, headers)
        return RetryShipperTasksResponse(header)
    
