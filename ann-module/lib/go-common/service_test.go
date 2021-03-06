// Copyright 2017 ZhongAn Information Technology Services Co.,Ltd.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package common

import (
	"testing"
)

func TestBaseServiceWait(t *testing.T) {

	type TestService struct {
		BaseService
	}
	ts := &TestService{}
	ts.BaseService = *NewBaseService(nil, "TestService", ts)
	ts.Start()

	go func() {
		ts.Stop()
	}()

	for i := 0; i < 10; i++ {
		ts.Wait()
	}

}
