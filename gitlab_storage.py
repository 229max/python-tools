 
#!/usr/bin/env python
# coding: utf8
 
"""
Gitlab storage for django file storage
create date: 2020/09/03
author: baikejian

How to use:  https://blog.csdn.net/max229max/article/details/108669769

"""

import base64
import logging
import os
import posixpath
from datetime import datetime
 
from django.conf import settings
from django.core.files.base import ContentFile, File
from django.core.files.storage import Storage
from django.utils.deconstruct import deconstructible
from django.utils.six import BytesIO
from django.utils.six.moves.urllib import parse as urlparse
 
from gitlab import Gitlab
 
 
@deconstructible
class GitlabStorage(Storage):
 
    def __init__(self, url, private_token, project_id, branch, api_version='3'):
        '''
        初始化gitlab实例
        url： https://xxxxxxxxxxx.com
        private_token：xsdfsdfsdfsdfsdfsdfsdf
        project_id: 123
        branch: master
        '''
        self.gitapi = Gitlab(url, private_token=private_token)
        self.project = self.gitapi.projects.get(project_id)
        self.branch = branch
        self._base_url = self.project.attributes.get('web_url')
 
 
    def _save(self, gitlab_path, content):
        logging.debug("Start saving...")
        logging.debug(type(content))
 
        commit_data = self.__create_commit_file_data(content, gitlab_path, f'auto commit {datetime.now()}')
        # commit file
        self.project.commits.create(commit_data)
        
        logging.debug("Save file success.")
        return gitlab_path
 
    def _open(self, git_path, mode='rb'):
        """
        获取git文件
        """
        logging.debug(f"Open file {git_path}.")
        f_raw = self.read(git_path)
        return ContentFile(f_raw)
 
    def read(self, git_path):
        try:
            logging.debug("Read file ...")
            gfile = self.project.files.get(file_path=git_path, ref=self.branch)
            base64_str = gfile.decode().decode('utf-8')
            raw_content = base64.b64decode(base64_str)
            return raw_content
        except Exception as e:
            raise Exception(f'Git file path incorrect! {e}')
 
 
    def delete(self, git_path):
        '''
        delete git file
        '''
        jMap = {}
        jMap["branch"] = self.branch
        jMap["commit_message"] = f'auto delete {datetime.now()}'
        
        jsonList = []
        aMap = {}
        aMap["action"] = "delete"
        aMap["file_path"] = gitlab_path
        jsonList.append(aMap)
 
        jMap["actions"] = jsonList
        self.project.commits.create(jMap)
        logging.debug("delete file success.")
 
 
    def exists(self, git_path):
        try:
            self.project.files.get(file_path=git_path, ref=self.branch)
            return True
        except Exception as e:
            return False
 
    
    def __create_commit_file_data(self, content, gitlab_path, message):
        """
        获取提交数据
        """
        jsonList = []
        jMap = {}
        jMap["branch"] = self.branch
        jMap["commit_message"] = message
        content.open(mode='rb')
        aMap = {}
        # 存在就更新， 不存在就创建
        if self.exists(gitlab_path):
            aMap["action"] = "update"
        else:
            aMap["action"] = "create"
        aMap["file_path"] = gitlab_path
        aMap["content"] = base64.b64encode(content.file.read()).decode("utf-8")
        jsonList.append(aMap)
 
        jMap["actions"] = jsonList
        return jMap
 
    def url(self, name):
        return urlparse.urljoin('/', name)
 
 
 
if __name__ == "__main__":
    GIT_URL = "http://gitlab.xxx.com"
    GIT_PRIVATE_TOKEN = "sdfsdfsdfsdfsdf"
    GIT_PROJECT_ID = "3172"
    GIT_DIR_PATH = "timelimit_attachment/"
    GIT_BRANCH = "master"
 
    gitapi = GitlabStorage(GIT_URL, GIT_PRIVATE_TOKEN, GIT_PROJECT_ID, GIT_BRANCH)
 
    f = open('./ops_platform/__init__.pyc')
    print(type(f))
    myfile = File(f)
    gitapi._save('timelimit_attachment/Dockerfile', myfile)
    readme = gitapi._open("timelimit_attachment/Dockerfile")
    print(readme.read())
