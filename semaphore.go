package main

type semaphore struct {
	c chan int
}

func newSemaphore(n int) *semaphore {
	s := &semaphore{
		c: make(chan int, n),
	}
	return s
}

func (s *semaphore) Acquire() {
	s.c <- 0
}

func (s *semaphore) Release() {
	<-s.c
}
