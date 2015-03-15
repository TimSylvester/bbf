#ifndef CONNCURENT_QUEUE_HPP
#define CONNCURENT_QUEUE_HPP

#include <algorithm>
#include <chrono>
#include <condition_variable>
#include <deque>
#include <exception>
#include <mutex>

template<typename T>
class concurrent_queue
{
public:
	concurrent_queue(size_t max_size = 0)
		: _max_size(max_size)
	{}

	size_t size() const;
	size_t max_size() const { return _max_size; }

	bool push(T const& item);

	template <typename TDuration>
	bool push(T const& item, TDuration timeout);

	template <typename TTime>
	bool push_until(T const& item, TTime deadline);

	bool pop(T& item);

	template <typename TDuration>
	bool pop(T& item, TDuration timeout);

	template <typename TTime>
	bool pop_until(T& item, TTime deadline);

	void stop();

private:
	typedef std::chrono::steady_clock steady_clock;
	typedef steady_clock::time_point time_point;
	typedef std::unique_lock<std::mutex> unique_lock;

	std::mutex              _mutex;
	std::deque<T>           _queue;
	std::condition_variable _empty_cond;
	std::condition_variable _full_cond;
	size_t                  _max_size;
};

template<typename T>
size_t concurrent_queue<T>::size() const
{
	unique_lock guard(_mutex);
	return _queue.size();
}

template <typename T>
bool concurrent_queue<T>::push(T const& item)
{
	return push_until(item, time_point::max());
}

template <typename T>
template <typename TDuration>
bool concurrent_queue<T>::push(T const& item, TDuration timeout)
{
	return push_until(item, steady_clock::now() + timeout);
}

template <typename T>
template <typename TTime>
bool concurrent_queue<T>::push_until(T const& item, TTime deadline)
{
	unique_lock lock(_mutex);

	if (!_full_cond.wait_until(lock, deadline,
		[&] { return _max_size == 0 || _queue.size() < _max_size; }))
	{
		return false;
	}

	_queue.push_back(item);
	lock.unlock();
	_empty_cond.notify_one();
	return true;
}

template <typename T>
bool concurrent_queue<T>::pop(T& item)
{
	return pop_until(item, time_point::max());
}

template <typename T>
template <typename TDuration>
bool concurrent_queue<T>::pop(T& item, TDuration timeout)
{
	return pop_until(item, steady_clock::now() + timeout);
}

template <typename T>
template <typename TDuration>
bool concurrent_queue<T>::pop_until(T& item, TDuration deadline)
{
	unique_lock lock(_mutex);

	if (!_empty_cond.wait_until(lock, deadline,
		[&] { return !_queue.empty(); }))
	{
		return false;
	}

	item = _queue.front();
	_queue.pop_front();
	lock.unlock();
	_full_cond.notify_one();
	return true;
}

template <typename T>
void concurrent_queue<T>::stop()
{
	_empty_cond.notify_one();
}

#endif
